# AI usage

## Tools used

- ChatGPT/Copilot SDK in VS Code for code review, Flask wiring, prompt design, and
  edge-case analysis.
- Ollama for the local runtime model. No cloud model is used by the application.

## Local model prompt

The system prompt identifies the input as untrusted data, disallows following commands
inside logs, excludes ordinary server errors and isolated failed logins, and requires
structured findings with attack type, severity, IP/ID, line evidence, reason, and action.

## Token budget

The application reserves a 1,000-token log-text budget per chunk. The remaining context
is reserved for the system prompt, compact cross-chunk suspect notes, and up to 350 output
tokens inside the 2,048-token model context.

## Prompt iterations and mistakes fixed

- Added explicit instructions that log content is data, not instructions, to reduce prompt
  injection from attacker-controlled request fields.
- Added a correlation pass so repeated activity split across chunks can become one finding.
- Added strict Ollama JSON schema output plus defensive parsing because a model response can
  be truncated or contain invalid JSON.
- Normal errors and one-off failed logins are excluded from the model's attack criteria.
- Added rule-backed candidate generation from the full log so the small model cannot relabel
  sensitive-path scanning as SQL injection or invent unsupported attack types.
- Added a short confirmation call for each rule-backed candidate. If confirmation fails, the
  evidence-based finding is retained and the job is marked partial instead of reporting a
  false clean result.

The application uses the actual system prompt and JSON schemas in `analyzer.py`; the model
does not receive executable instructions from log content.
