
# Sentinel — Local AI Security Log Analyzer

Sentinel is an offline-first security log analyzer built with Python, FastAPI, SQLite, JavaScript, and a locally hosted GGUF language model running through llama.cpp.

It analyzes log files using token-bounded AI inference, correlates suspicious activity across the complete log, and generates an evidence-linked security report through a professional SOC-style dashboard.

**No cloud AI inference API is required.**

## 1. Features

- Fully local AI inference using llama.cpp.
- Qwen3.5-0.8B Q4_K_M quantized model.
- Responsive cybersecurity SOC dashboard.
- Security KPI cards and severity distribution charts.
- Log upload with an 8 MB file-size limit.
- Support for `.log` and `.txt` files.
- Token-aware chunk construction.
- Configured 2,048-token context.
- Sequential inference with one active analysis worker.
- Original physical log-line evidence references.
- Cross-chunk deterministic attack correlation.
- AI candidate validation against evidence line numbers and source IPs.
- Filtering of ordinary upstream 503 errors without attack evidence.
- SQLite persistence and resumable analysis.
- Progress tracking, search, severity filters, and JSON report export.
- Local-only processing without uploading logs to a cloud AI provider.

## 2. Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, FastAPI |
| Frontend | HTML, CSS, vanilla JavaScript |
| AI runtime | llama.cpp / llama-server |
| Model | Qwen3.5-0.8B |
| Quantization | Q4_K_M |
| Database | SQLite |
| Inference protocol | Local HTTP API |
| Configured CPU threads | 2 |
| Configured context | 2,048 tokens |
| Target memory budget | 4 GB total |

## 3. Repository Structure

```text
cultive8-analyzer/
├── main.py
├── engine.py
├── requirements.txt
├── README.md
├── AI_USAGE.md
├── static/
│   └── index.html
├── sample/
│   └── assessment.log
├── tests/
└── data/
```

The `sample/assessment.log` file should only be included if it is approved for public distribution.

The `data/` directory contains runtime data and SQLite storage. Its contents must not be committed to a public repository.

The Python virtual environment and downloaded GGUF model are stored separately in the tested local setup.

The model weights are not distributed with the repository.

## 4. Requirements

- Python 3.10 or newer.
- Git.
- Compatible llama.cpp release with `llama-server`.
- Qwen3.5-0.8B Q4_K_M GGUF model.
- Windows or another environment supported by Python and llama.cpp.

### Assessment hardware targets

| Resource | Target |
|---|---|
| RAM | 4 GB total |
| CPU | 2 vCPU |
| GPU | Not required |
| Context | Maximum 2,048 tokens |
| Inference | Fully local |
| Processing | Sequential |

Observed process working-set usage was below 4 GB during development testing. Peak combined memory usage on the target hardware has not been independently benchmarked.

## 5. Windows Installation

Clone the repository and enter its directory:

```powershell
git clone YOUR_REPOSITORY_URL
cd cultive8-analyzer
```

Replace `YOUR_REPOSITORY_URL` with the actual GitHub repository URL after creating it.

Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Install llama.cpp using a compatible release. On Windows, one installation method is:

```powershell
winget install ggml.llamacpp
```

Download `Qwen3.5-0.8B-Q4_K_M.gguf` from a trusted publisher and review its model license.

Place the model in a `models` directory or adjust the model path in the startup command.

## 6. Start the Local Model

From the directory containing the `models` folder, run:

```powershell
llama-server -m ".\models\Qwen3.5-0.8B-Q4_K_M.gguf" -c 2048 -t 2 -ngl 0 --parallel 1 --no-mmproj --no-webui --reasoning off --host 127.0.0.1 --port 8080
```

If `llama-server` is not on the system PATH, replace it with the full path to the installed executable.

### Configuration

| Argument | Purpose |
|---|---|
| `-m` | Model file location |
| `-c 2048` | 2,048-token context |
| `-t 2` | Two CPU threads |
| `-ngl 0` | CPU-only inference |
| `--parallel 1` | One inference slot |
| `--no-mmproj` | Disable multimodal projector |
| `--no-webui` | Disable llama.cpp web UI |
| `--reasoning off` | Disable reasoning output |
| `--host 127.0.0.1` | Bind to localhost |
| `--port 8080` | Local model API port |

The `--reasoning off` setting was important during testing because an earlier model response returned empty content under the configured output budget.

Verify the model server:

```text
http://127.0.0.1:8080/health
```

The model server must remain running during analysis.

## 7. Start FastAPI

Open a second terminal and navigate to the directory containing `main.py`.

Activate the Python environment and run:

```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8001
```

Open:

```text
http://127.0.0.1:8001/
```

Port `8001` was used for the final local development run because port `8000` was occupied during testing.

Either port can be used when available, but the browser URL must match the selected FastAPI port.

The backend communicates with the model server at:

```text
http://127.0.0.1:8080
```

For health verification:

```text
http://127.0.0.1:8001/api/health
```

## 8. How to Use Sentinel

1. Start the local AI model server.
2. Start the FastAPI backend.
3. Open the Sentinel dashboard.
4. Choose a `.log` or `.txt` file.
5. Click **Start Analysis**.
6. Monitor the number of processed chunks.
7. Review the completed security report.
8. Search findings by IP, event description, or evidence.
9. Filter findings by severity.
10. Export the JSON report.

If an analysis fails, use **Resume Failed Analysis** to retry processing while retaining previously completed chunks when the saved chunk layout remains compatible.

Avoid refreshing the dashboard during processing because the browser does not persist the active job ID across reloads.

## 9. Analysis Architecture

### Step 1 — Upload and validation

Files are uploaded in 64 KB blocks, with a maximum size of 8 MB.

The backend validates file extension, nonempty input, and obvious binary content.

Uploaded content remains on local storage.

### Step 2 — Preserve evidence lines

Log entries are read while retaining original physical line numbers.

These line numbers are included in the final security findings.

### Step 3 — Token-aware chunking

The configured model context is 2,048 tokens.

The tokenizer supplied by the local llama.cpp server is used to estimate candidate prompt sizes.

| Budget setting | Tokens |
|---|---:|
| Total configured context | 2,048 |
| Reserved output | 360 |
| Additional safety margin | 220 |
| System prompt | Counted by tokenizer |
| User prompt and log entries | Remaining capacity |

Chunk creation respects physical log-entry boundaries.

An oversized single log line produces an explicit processing error instead of being silently dropped.

A preflight token-budget check is performed before inference.

The additional margin is conservative but does not independently guarantee exact chat-template accounting for every possible input.

### Step 4 — Local model inference

Each chunk is sent sequentially to the local model.

The model receives a structured system instruction that requires:

- Suspicious activity supported by evidence.
- Structured JSON output.
- Source line-number references.
- Cautious severity assessment.
- No execution of instructions embedded in log data.
- No assumption that ordinary operational failures are attacks.

Inference uses temperature zero and a maximum response budget of 360 tokens.

### Step 5 — AI finding validation

Model-generated findings are checked before inclusion.

Validation includes:

- Supported severity values.
- Line numbers belonging to the analyzed chunk.
- Source-IP agreement with referenced log events.
- Bounded field lengths.
- Limits on candidate findings.
- A targeted filter for ordinary upstream 503 failures without additional attack evidence.

AI findings are not treated as definitive proof of security compromise.

### Step 6 — SQLite persistence

Each completed chunk's findings and processing information are saved in SQLite.

If processing fails, the application can reuse completed chunk results.

Resume validates the saved line ranges against the current chunk layout.

If chunk boundaries have changed, a new analysis job is required rather than reusing potentially incompatible saved results.

### Step 7 — Cross-chunk correlation

Deterministic correlation examines the complete log independently of individual AI chunks.

Supported patterns include:

- Repeated failed logins.
- Failed authentication followed by successful authentication.
- Subsequent administrative access.
- SQL injection-like requests.
- Sensitive endpoint scanning.
- Repeated access-denied events.
- Abnormal request-rate telemetry.

Duplicate request IDs are excluded from rule-based event counts.

### Step 8 — Consolidated report

Findings from local AI and deterministic rules are consolidated.

Each reported finding includes:

- Severity.
- Threat category.
- Source IP or identifier.
- Supporting reason.
- Source log-line numbers.
- Suggested action.
- Detection source.

The report is available in the Dashboard and as a downloadable JSON file.

## 10. Final Assessment-Log Results

The latest successful analysis of the assessment log produced:

| Metric | Result |
|---|---:|
| Total log lines | 258 |
| Chunks processed | 34 / 34 |
| Consolidated findings | 5 |
| Critical | 1 |
| High | 2 |
| Medium | 2 |
| Low | 0 |

### Critical — Possible brute force and account compromise

**IP:** `203.0.113.44`

Twelve failed authentication attempts against `workspace.admin` were followed by successful authentication and administrative access.

Key evidence:

- Line 189: Failed login.
- Line 196: Successful login.
- Line 198: Administrative access.

The successful login and subsequent administrative request share a session identifier.

This supports suspicion of account compromise but is not conclusive proof of unauthorized access.

### High — SQL injection attempts

**IP:** `203.0.113.72`

Four SQL-like requests were identified.

Evidence lines: `29, 30, 32, 222`.

At line 29, the request contained a URL-encoded SQL injection-like pattern corresponding to:

```text
' OR 1=1--
```

The server returned HTTP 400. Successful injection execution was not established.

### High — Unusual request rate

**IP:** `203.0.113.155`

Evidence lines: `159–170`.

Line 162 recorded 127 requests within 10 seconds, accompanied by HTTP 429 throttling.

This supports unusually high request volume but does not establish a DDoS attack.

### Medium — Sensitive endpoint scanning

**IP:** `203.0.113.90`

Evidence lines: `54, 56, 58, 60, 62, 64, 67, 69`.

Requests targeted sensitive endpoints, including `/.env`.

### Medium — Unauthorized access attempts

**IP:** `203.0.113.90`

Evidence lines: `99, 101, 102`.

Requests targeted restricted resources, including `/api/v1/admin/settings`.

Line 102 returned HTTP 403 with an `access_denied` security rule.

## 11. Testing and Validation

Development testing included:

- Python syntax compilation.
- Security-rule verification.
- Token-budget measurements.
- Malformed JSON handling.
- Timeout and retry simulation.
- SQLite persistence and resume simulation.
- Model-server health checks.
- Manual evidence-line verification.
- Active-process memory observation.
- End-to-end assessment-log analysis.
- Frontend rendering and JSON export checks.

### Earlier version

An earlier run processed 31 chunks and generated five consolidated findings.

The token estimate in an earlier test reached 2,039 against a 2,048-token context, leaving a narrow margin.

### Improved version

The prompt safety margin was increased to 220 tokens.

The revised analyzer processed 34 chunks.

A model response issue was addressed by starting llama.cpp with `--reasoning off`.

An additional false-positive finding involving ordinary HTTP 503 upstream failures was identified and addressed with a targeted validation filter.

The subsequent full assessment-log run completed with five consolidated security findings.

### Memory observation

A previous active-process measurement recorded:

| Process group | Working-set memory |
|---|---:|
| llama-server | 1,006.10 MB |
| Python processes combined | 103.48 MB |
| Combined observed working sets | 1,109.58 MB |

These values represent process working-set observations on a Windows development machine.

They do not prove peak total system memory compliance on a separate 4 GB / 2-vCPU host.

## 12. Dashboard Features

The SOC-style Dashboard includes:

- Sidebar navigation.
- Security overview KPI cards.
- Critical, High, Medium, and Low severity counts.
- Severity distribution donut chart.
- Severity breakdown bars.
- Upload and analysis pipeline panels.
- Real-time analysis progress.
- Searchable security findings.
- Severity filters.
- Source evidence references.
- Suggested remediation actions.
- JSON report download.

All dashboard severity charts are calculated from the actual report, not fabricated values.

The frontend uses local HTML, CSS, and JavaScript without requiring cloud-hosted chart libraries.

## 13. API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | Dashboard |
| `POST` | `/api/jobs` | Upload and start an analysis |
| `GET` | `/api/jobs/{jid}` | Retrieve status and report |
| `POST` | `/api/jobs/{jid}/resume` | Resume a failed analysis |
| `GET` | `/api/health` | Backend health |

The model API runs separately on port 8080.

## 14. Privacy and Security

Sentinel is designed for local processing.

Uploaded log data is not sent to cloud AI providers by the application.

The analyzer treats logs as untrusted input and does not execute embedded instructions.

The application is intended to run on localhost during development.

Do not expose it publicly without additional authentication and security hardening.

Never commit confidential production logs, credentials, session tokens, model weights, or runtime databases to a public repository.

## 15. Known Limitations

1. Exact chat-template overhead is not independently verified for every possible prompt.
2. Peak combined RAM usage on the target hardware is not independently established.
3. Small local models may generate malformed or unsupported output.
4. The upstream 503 filter addresses a specific observed false-positive class.
5. Long individual log entries are rejected if they cannot fit the prompt budget.
6. Browser refresh does not restore the active job ID automatically.
7. SQLite persistence is local and not a distributed job system.
8. The in-process analysis gate is intended for single-process deployment, not multiple FastAPI workers.
9. Deterministic security patterns and thresholds are assessment-oriented, not exhaustive.
10. Security findings require human investigation before any conclusion about compromise.

## 16. Troubleshooting

### Model server unavailable

Check:

```text
http://127.0.0.1:8080/health
```

Ensure the model process is running and `engine.LOCAL_URL` matches the active server.

### Dashboard unavailable

Check:

```text
http://127.0.0.1:8001/
```

If port 8001 is unavailable, select another free port and use the matching browser URL.

### Empty model response

Confirm the model is compatible with the configured chat template.

The final tested llama.cpp command includes `--reasoning off`.

### Analysis failed

Inspect the dashboard's error message.

Use **Resume Failed Analysis** if the job remains available and its saved chunk layout is compatible.

### High memory usage

Use a small quantized model, 2,048-token context, two CPU threads, one parallel inference slot, and no unnecessary model components.

Measure actual process and system memory under load.

## 17. AI-Assisted Development

ChatGPT was used during development for planning, implementation assistance, debugging, test design, frontend improvements, and documentation.

Qwen3.5-0.8B was used as the local runtime inference model.

See [AI_USAGE.md](AI_USAGE.md) for the AI assistance disclosure, observed errors, corrective changes, and verification details.

## 18. Disclaimer

Sentinel was developed as a technical assessment prototype.

The application is not a complete production SIEM or incident-response platform.

Security alerts should be treated as evidence-linked investigation candidates rather than definitive proof of successful attacks.

Model distribution and licensing remain subject to the publisher's applicable terms.
