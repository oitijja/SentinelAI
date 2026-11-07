
"""Sentinel: offline-first security log analysis API."""

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from engine import (
    chunk_stream,
    extract_signals,
    form_prompt,
    local_chat,
    merge_findings,
    parse_json,
    valid_ai,
)


ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
STATIC = ROOT / "static"

DATA.mkdir(exist_ok=True)

DB = DATA / "jobs.sqlite3"
MAX_UPLOAD = 8 * 1024 * 1024

# Database writes and job launch coordination.
db_lock = threading.Lock()

# Only one analysis runs in this Python process at a time.
analysis_gate = threading.Lock()

app = FastAPI(
    title="Sentinel - Local AI Security Log Analyzer",
    description="Offline security-log analysis using llama.cpp",
)

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC)),
    name="static",
)


# --------------------------------------------------
# Database
# --------------------------------------------------

def connect():
    db = sqlite3.connect(DB, timeout=20)
    db.row_factory = sqlite3.Row
    return db


def init():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                filename TEXT,
                status TEXT,
                error TEXT,
                total INTEGER,
                completed INTEGER,
                report TEXT,
                created REAL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS batches (
                job_id TEXT,
                batch INTEGER,
                lines TEXT,
                findings TEXT,
                raw TEXT,
                seconds REAL,
                PRIMARY KEY (job_id, batch)
            )
        """)


init()


def set_job(jid, **fields):
    if not fields:
        return

    # Field names are supplied internally, not from HTTP input.
    columns = ", ".join(
        f"{key}=?" for key in fields
    )

    values = list(fields.values()) + [jid]

    with db_lock:
        with connect() as db:
            db.execute(
                f"UPDATE jobs SET {columns} WHERE id=?",
                values,
            )


def get_job(jid):
    with connect() as db:
        row = db.execute(
            "SELECT * FROM jobs WHERE id=?",
            (jid,),
        ).fetchone()

    if row is None:
        raise HTTPException(404, "Job not found")

    return dict(row)


def saved_batches(jid):
    with connect() as db:
        rows = db.execute(
            """
            SELECT batch, lines, findings
            FROM batches
            WHERE job_id=?
            ORDER BY batch
            """,
            (jid,),
        ).fetchall()

    return {
        int(row["batch"]): {
            "lines": json.loads(row["lines"]),
            "findings": json.loads(row["findings"]),
        }
        for row in rows
    }


# --------------------------------------------------
# Single-job execution control
# --------------------------------------------------

def launch_job(jid):
    """
    Reserve the local analysis worker before thread launch.

    Return HTTP 409 when another job is active.
    """

    if not analysis_gate.acquire(blocking=False):
        raise HTTPException(
            409,
            "Another analysis is already running. "
            "Wait until it finishes before starting a new one.",
        )

    try:
        worker = threading.Thread(
            target=run_analysis,
            args=(jid,),
            daemon=True,
            name=f"sentinel-{jid}",
        )

        worker.start()

    except Exception:
        analysis_gate.release()
        raise


# --------------------------------------------------
# Analysis
# --------------------------------------------------

def run_analysis(jid):
    path = DATA / f"{jid}.log"

    try:
        set_job(
            jid,
            status="running",
            error="",
        )

        # Use identical context for chunk sizing and inference.
        # This avoids accidentally changing the token requirement
        # between the initial chunk calculation and AI calls.
        #
        # Cross-chunk attack correlation is performed independently
        # over the complete file by extract_signals().
        prompt_context = "none"

        chunks = list(
            chunk_stream(
                path,
                context=prompt_context,
            )
        )

        saved = saved_batches(jid)

        # A changed token margin or model can change chunk boundaries.
        # Never reuse saved results for a different range of lines.
        for index, saved_data in saved.items():

            if index >= len(chunks):
                raise RuntimeError(
                    "Saved chunk layout differs from the current "
                    "configuration. Start a new analysis job."
                )

            current_chunk = chunks[index]

            current_range = [
                current_chunk[0][0],
                current_chunk[-1][0],
            ]

            if saved_data["lines"] != current_range:
                raise RuntimeError(
                    "Saved chunk layout differs from the current "
                    "configuration. Start a new analysis job."
                )

        set_job(
            jid,
            total=len(chunks),
            completed=len(saved),
        )

        ai_findings = []

        for index, chunk in enumerate(chunks):

            # Resume: reuse already verified chunk results.
            if index in saved:
                ai_findings.extend(
                    saved[index]["findings"]
                )
                continue

            started = time.monotonic()

            prompt = form_prompt(
                chunk,
                prompt_context,
            )

            # engine.local_chat verifies the token budget
            # immediately before sending the request.
            raw = local_chat(prompt)

            allowed_lines = {
                line_number
                for line_number, _ in chunk
            }

            # Verify both referenced line numbers and source IPs.
            findings = valid_ai(
                parse_json(raw),
                allowed_lines,
                entries=chunk,
            )

            elapsed = round(
                time.monotonic() - started,
                2,
            )

            line_range = [
                chunk[0][0],
                chunk[-1][0],
            ]

            # Commit the chunk before updating job progress.
            with db_lock:
                with connect() as db:
                    db.execute(
                        """
                        INSERT OR REPLACE INTO batches
                        (job_id, batch, lines, findings, raw, seconds)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            jid,
                            index,
                            json.dumps(line_range),
                            json.dumps(findings),
                            raw[:10000],
                            elapsed,
                        ),
                    )

            ai_findings.extend(findings)

            set_job(
                jid,
                completed=index + 1,
            )

        # Correlate across the entire log, not just AI chunks.
        rule_findings, duplicate_lines = extract_signals(
            path
        )

        final_findings = merge_findings(
            rule_findings + ai_findings
        )

        with open(
            path,
            "r",
            encoding="utf-8-sig",
            errors="replace",
        ) as file:
            line_count = sum(1 for _ in file)

        report = {
            "findings": final_findings,
            "chunk_count": len(chunks),
            "line_count": line_count,
            "duplicate_lines_ignored": duplicate_lines,
            "notes": [
                (
                    "AI evidence line numbers and source IPs "
                    "are checked against the analyzed chunk."
                ),
                (
                    "Cross-file correlation is deterministic "
                    "and independent of chunk boundaries."
                ),
                (
                    "Findings indicate suspicious activity, "
                    "not proof of actual compromise."
                ),
            ],
        }

        set_job(
            jid,
            status="complete",
            error="",
            report=json.dumps(report),
            completed=len(chunks),
        )

    except Exception as exc:
        set_job(
            jid,
            status="failed",
            error=str(exc)[:700],
        )

    finally:
        analysis_gate.release()


# --------------------------------------------------
# Dashboard
# --------------------------------------------------

@app.get("/")
def home():
    return FileResponse(
        STATIC / "index.html"
    )


# --------------------------------------------------
# File upload
# --------------------------------------------------

@app.post("/api/jobs")
def upload(file: UploadFile = File(...)):

    filename = file.filename or ""

    if not filename.lower().endswith(
        (".log", ".txt")
    ):
        raise HTTPException(
            400,
            "Only .log and .txt files are accepted",
        )

    # Reject a second job before writing an unnecessary upload.
    if analysis_gate.locked():
        raise HTTPException(
            409,
            "Another analysis is already running.",
        )

    jid = uuid.uuid4().hex[:14]
    path = DATA / f"{jid}.log"

    size = 0
    inserted = False

    try:
        with open(path, "wb") as output:

            while True:
                block = file.file.read(65536)

                if not block:
                    break

                size += len(block)

                if size > MAX_UPLOAD:
                    raise HTTPException(
                        413,
                        "File exceeds 8 MB limit",
                    )

                output.write(block)

        if size == 0:
            raise HTTPException(
                400,
                "File is empty",
            )

        with open(path, "rb") as source:
            if b"\x00" in source.read(4096):
                raise HTTPException(
                    400,
                    "Binary files are not supported",
                )

        with db_lock:
            with connect() as db:
                db.execute(
                    """
                    INSERT INTO jobs
                    (id, filename, status, error,
                     total, completed, report, created)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        jid,
                        filename,
                        "queued",
                        "",
                        0,
                        0,
                        None,
                        time.time(),
                    ),
                )

        inserted = True

        # Acquire the execution slot before returning success.
        launch_job(jid)

        return {
            "id": jid,
            "status": "queued",
        }

    except Exception:

        path.unlink(missing_ok=True)

        if inserted:
            with db_lock:
                with connect() as db:
                    db.execute(
                        "DELETE FROM jobs WHERE id=?",
                        (jid,),
                    )

        raise

    finally:
        file.file.close()


# --------------------------------------------------
# Job status
# --------------------------------------------------

@app.get("/api/jobs/{jid}")
def status(jid: str):

    job = get_job(jid)

    with connect() as db:
        timing = db.execute(
            """
            SELECT SUM(seconds) AS elapsed
            FROM batches
            WHERE job_id=?
            """,
            (jid,),
        ).fetchone()["elapsed"]

    result = {
        key: job[key]
        for key in (
            "id",
            "filename",
            "status",
            "error",
            "total",
            "completed",
        )
    }

    result["model_seconds"] = round(
        timing or 0,
        2,
    )

    if job["report"]:
        result["report"] = json.loads(
            job["report"]
        )

    return result


# --------------------------------------------------
# Resume
# --------------------------------------------------

@app.post("/api/jobs/{jid}/resume")
def resume(jid: str):

    job = get_job(jid)

    if job["status"] == "complete":
        return {"status": "complete"}

    # Atomic worker reservation prevents two resume
    # requests from starting overlapping analysis threads.
    if analysis_gate.locked():
        raise HTTPException(
            409,
            "An analysis is already running.",
        )

    set_job(
        jid,
        status="queued",
        error="",
    )

    launch_job(jid)

    return {
        "status": "queued",
    }


# --------------------------------------------------
# Health
# --------------------------------------------------

@app.get("/api/health")
def health():
    return {
        "ok": True,
        "service": "Sentinel",
        "model": "llama.cpp",
        "model_url": "http://127.0.0.1:8080",
        "analysis_busy": analysis_gate.locked(),
    }
