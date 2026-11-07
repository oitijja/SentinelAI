"""Isolated failure-and-resume test; does not touch existing jobs."""
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
import main


def run_test():
    with tempfile.TemporaryDirectory(
    prefix="sentinel-resume-test-",
    ignore_cleanup_errors=True
) as folder:
        temporary = Path(folder)
        job_id = "resume_test"
        (temporary / (job_id + ".log")).write_text(
            '{"client_ip":"192.0.2.1"}\n'
            '{"client_ip":"192.0.2.2"}\n'
            '{"client_ip":"192.0.2.3"}\n',
            encoding="utf-8",
        )
        chunks = [[(1, 'event 1')], [(2, 'event 2')], [(3, 'event 3')]]
        findings = [
            {"type": "Suspicious activity", "severity": "Low", "ip": "192.0.2.1",
             "reason": "Test event", "action": "Review", "lines": [1]}
        ]
        calls = []
        fail_once = {"value": True}

        def fake_chat(prompt):
            calls.append(prompt)
            if "event 2" in prompt and fail_once["value"]:
                fail_once["value"] = False
                raise main.ModelError("Simulated model failure")
            if "event 1" in prompt:
                return json.dumps({"findings": findings})
            return '{"findings": []}'

        def fake_chunks(path, **kwargs):
            return iter(chunks)

        with patch.object(main, "DATA", temporary), \
             patch.object(main, "DB", temporary / "test.sqlite3"), \
             patch.object(main, "chunk_stream", side_effect=fake_chunks), \
             patch.object(main, "local_chat", side_effect=fake_chat), \
             patch.object(main, "extract_signals", return_value=([], [])):
            main.init()
            with main.connect() as db:
                db.execute(
                    'INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)',
                    (job_id, 'test.log', 'queued', '', 0, 0, None, 0),
                )

            main.run_analysis(job_id)
            first = main.get_job(job_id)
            with main.connect() as db:
                saved = db.execute('SELECT COUNT(*) FROM batches WHERE job_id=?', (job_id,)).fetchone()[0]
            assert first['status'] == 'failed', first
            assert saved == 1, f"Expected 1 saved chunk, got {saved}"
            print("PASS: simulated failure preserved the first completed chunk")

            calls_before_resume = len(calls)
            main.run_analysis(job_id)
            final = main.get_job(job_id)
            resume_calls = calls[calls_before_resume:]
            assert final['status'] == 'complete', final
            assert final['completed'] == 3, final
            assert len(resume_calls) == 2, f"Expected 2 fresh AI calls, got {len(resume_calls)}"
            assert all('event 1' not in prompt for prompt in resume_calls), "First chunk was repeated"
            report = json.loads(final['report'])
            assert any(f['ip'] == '192.0.2.1' and 1 in f['lines'] for f in report['findings']), report
            with main.connect() as db:
                saved_final = db.execute('SELECT COUNT(*) FROM batches WHERE job_id=?', (job_id,)).fetchone()[0]
            assert saved_final == 3, saved_final
            print("PASS: resume skipped saved chunk and processed only remaining chunks")
            print("PASS: saved finding appears in final report")
            print("RESUME AND PERSISTENCE TEST PASSED")


if __name__ == '__main__':
    run_test()
