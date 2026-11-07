import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import ollama
from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

from analyzer import SEV, analyze_logs


BASE_DIR = Path(__file__).resolve().parent
JOB_DIR = BASE_DIR / "jobs"
UPLOAD_DIR = JOB_DIR / "uploads"
REPORT_DIR = JOB_DIR / "reports"
ALLOWED_EXTENSIONS = {".log", ".txt"}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024

for directory in (UPLOAD_DIR, REPORT_DIR):
    directory.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

executor = ThreadPoolExecutor(max_workers=1)
jobs = {}
jobs_lock = threading.Lock()


def new_job():
    job_id = uuid.uuid4().hex
    with jobs_lock:
        jobs[job_id] = {
            "status": "queued",
            "progress": 0,
            "total": None,
            "findings": [],
            "error": None,
            "filename": None,
        }
    return job_id


def update_job(job_id, **values):
    with jobs_lock:
        if job_id in jobs:
            jobs[job_id].update(values)


def get_job(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
        return dict(job) if job else None


def run_analysis(job_id, path):
    try:
        update_job(job_id, status="running")

        def progress(done, total):
            update_job(job_id, progress=done, total=total)

        findings, meta = analyze_logs(
            str(path),
            budget=1000,
            on_progress=progress,
            on_partial=lambda partial: update_job(job_id, findings=partial),
        )
        findings.sort(key=lambda finding: -SEV.index(finding["severity"]))
        failed_calls = len(meta["failed_chunks"]) + meta["failed_confirmations"]
        update_job(
            job_id,
            status="partial" if failed_calls else "complete",
            findings=findings,
            meta=meta,
        )
    except Exception as exc:
        update_job(job_id, status="failed", error=str(exc))
    finally:
        try:
            path.unlink()
        except OSError:
            pass


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/jobs")
def create_job():
    try:
        ollama.Client(timeout=3).list()
    except Exception:
        return jsonify(error="Ollama is not running. Start it and try again."), 503

    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify(error="Choose a .log or .txt file."), 400

    filename = secure_filename(uploaded.filename)
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        return jsonify(error="Only .log and .txt files are accepted."), 400

    job_id = new_job()
    path = UPLOAD_DIR / f"{job_id}-{filename}"
    try:
        uploaded.save(path)
    except OSError:
        with jobs_lock:
            jobs.pop(job_id, None)
        return jsonify(error="The upload could not be saved."), 500

    update_job(job_id, filename=filename)
    executor.submit(run_analysis, job_id, path)
    return jsonify(job_id=job_id), 202


@app.get("/api/jobs/<job_id>")
def job_status(job_id):
    job = get_job(job_id)
    if job is None:
        return jsonify(error="Job not found."), 404
    return jsonify(job)


@app.get("/api/jobs/<job_id>/report")
def job_report(job_id):
    job = get_job(job_id)
    if job is None:
        return jsonify(error="Job not found."), 404
    if job["status"] not in {"complete", "partial"}:
        return jsonify(error="The analysis is not complete.", status=job["status"]), 409
    return jsonify(
        filename=job["filename"],
        findings=job["findings"],
        finding_count=len(job["findings"]),
    )


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(error="The file is larger than the 2 MB limit."), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
