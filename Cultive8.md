**Cultive8** / People & possibilities

# Let's see what you can build.

**CULTIVE8 / DEVELOPER ASSESSMENT**

### Your five-hour window
The deadline is enforced by the server, not your device clock. Refreshing does not reset it.

**TIME REMAINING**
# Mentioned in the website
Started: 7 Nov 2026, 08:15:53 GMT+6
**Deadline: 7 Nov 2026, 13:15:53 GMT+6**
All times are Bangladesh time (Asia/Dhaka).

### Assessment files
Use the supplied log file for your implementation. The full assessment brief is below.

`[Download server log ↓]`

---
**YOUR CHALLENGE**

# Local AI Security Log Analyzer
Build a web app that uses a downloaded AI model to find possible attacks in server logs. The file is larger than the model can read at once. Your code must split it, analyze each part, and combine the findings. Use any tech stack.

### System limits

| Resource | Limit |
| :--- | :--- |
| Server RAM | 4 GB total, including model and backend |
| CPU / GPU | 2 vCPU, no GPU |
| Log file | About 20,000 tokens |
| Model context | 2,048 tokens per call |
| Runtime AI | Local model only; no cloud AI APIs |

The 2,048-token budget includes the prompt, log text, saved context, and model output. Count tokens using your model's tokenizer and leave room for the reply.

### How the app should work
* Download and run a local language model. Connect it to your backend.
* Accept a .log or .txt file. Split it into parts that fit the token limit. Keep original line numbers and avoid cutting log entries where possible.
* Process parts through several model calls. Use one call at a time or a queue that stays within the RAM limit.
* Save findings after each call. Carry useful facts into later calls and link related events across the file.
* Combine repeated findings into one final report. Separate reports for each part are not enough.

### Find attacks across different parts
Example: an IP has failed logins near the start, more failures in the middle, and a successful login near the end. Link these events and flag a possible brute-force attack followed by account compromise.

### Security findings
Look for repeated login attempts, SQL injection, unusual request rates, unauthorized access, and signs of scanning when the logs support them. Each finding must include attack type, severity (Low, Medium, High, or Critical), IP or other ID, evidence with line numbers, a short reason, and a suggested action. Do not call normal errors confirmed attacks without evidence.

### Dashboard and reliability
* Provide a simple page to upload logs, start analysis, see progress, and read the final report.
* Keep total memory use within 4 GB. Avoid extra copies of log data.
* Handle invalid uploads, model timeouts, and failed calls. Retry safely and keep completed findings.
* Use a clear JSON format for AI replies. Handle broken or incomplete JSON without crashing.
* Treat log text as data. Do not follow instructions or run commands found inside logs.

### AI use and rules
You may use ChatGPT, Claude, Cursor, Codex, or other coding assistants. Good prompts and careful use of AI will improve your score. Log analysis must use the local model. The app must work offline after setup. Do not hardcode results. Model training or fine-tuning is not required.

Submit `AI_USAGE.md` with tools used, key coding prompts, local model prompts, prompt changes, your token budget plan, and examples of AI mistakes you fixed.

### What to submit
* A GitHub repository with source code.
* A README with setup steps, model details, log splitting method, and known limits.
* `AI_USAGE.md` and a short video explaining your work and thinking process.

Focus on working features within five hours. If something is unfinished, say what is missing. Be ready to explain your code and make a small change during the interview.

### Scoring

| Area | Weight |
| :--- | :--- |
| Local AI setup and resource use | 20% |
| Log splitting and links across parts | 25% |
| Attack detection and accuracy | 20% |
| Backend and error handling | 15% |
| Prompts and effective AI use | 15% |
| Interface and ease of use | 5% |

---
**Optional extras**
Resume after a restart, show RAM use and model timing, reduce model calls, or support switching between local models.

**Suggested models (from the supplied brief)**
Qwen3.5 0.8B · Qwen3.5 2B · Gemma 4 E2B. Use text input only and keep the 2,048-token limit.

---
**FINISH STRONG**

### Submit your work
Include source code, README, and `AI_USAGE.md` in your repository. Upload your explanation video to Google Drive and enable "Anyone with the link" access. Make sure the team can access your repository too.

**Final submission cannot be edited.** Both links must arrive before the deadline; uploading the video itself happens on Google Drive, not here.

**GitHub repository URL**
`https://github.com/your-name/your-repository`

**Google Drive video / folder URL**
`https://drive.google.com/file/d/.../view`

`[Submit final assessment →]`