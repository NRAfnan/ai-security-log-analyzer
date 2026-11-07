# Local AI Security Log Analyzer

## Setup

1. Install Python 3.11+ and Ollama.
2. Start Ollama and download the local model:

   ```powershell
   ollama pull qwen3.5:2b
   ```

3. Create/activate a virtual environment and install dependencies:

   ```powershell
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

4. Start the Flask app:

   ```powershell
   python app.py
   ```

5. Open `http://127.0.0.1:5000`.

## Design

- `splitter.py` parses each line, preserves original line numbers, normalizes JSON logs,
  and creates chunks using a tokenizer when `tokenizer.json` is available.
- `state.py` keeps compact per-IP facts across chunks, including failed/successful logins,
  SQL injection/traversal indicators, sensitive paths, and request-rate signals.
- `analyzer.py` sends one chunk at a time to Ollama, validates model findings, retries
  transient failures, and performs a final correlation call before merging duplicates.
- `app.py` provides upload, progress, and final-report JSON endpoints. A single-worker
  executor ensures only one model analysis runs at a time, keeping RAM use predictable.

The model sees log text as data. It is explicitly told not to follow instructions in logs.
Uploads are limited to 2 MB, which is deliberately sized for the assessment's approximately
20,000-token input and serialized CPU analysis. Only `.log` and `.txt` files are accepted.
The app checks that Ollama is reachable before accepting an upload. If individual model
calls fail, rule-backed findings are retained and the job is marked `partial`.

## API

- `POST /api/jobs` with multipart field `file` returns `{ "job_id": "..." }`.
- `GET /api/jobs/<job_id>` returns progress and status.
- `GET /api/jobs/<job_id>/report` returns the merged findings after completion.

## Known limits

Job state is in memory and is lost if the process restarts. The optional resume/persistence
feature was intentionally left out to prioritize the core assessment flow. The analysis is
single-worker because the local model and 4 GB RAM limit favor serialized calls.
