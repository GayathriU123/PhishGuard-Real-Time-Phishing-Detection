import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from backend.app.config import DATABASE_PATH


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with _connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                input_type TEXT NOT NULL CHECK(input_type IN ('url', 'email')),
                submitted_at TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_band TEXT NOT NULL,
                review_status TEXT NOT NULL,
                model_version TEXT,
                summary TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cases_submitted
                ON cases(submitted_at DESC);
            CREATE INDEX IF NOT EXISTS idx_cases_verdict
                ON cases(verdict);
            CREATE INDEX IF NOT EXISTS idx_cases_review
                ON cases(review_status);
            CREATE TABLE IF NOT EXISTS review_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL REFERENCES cases(id),
                actor TEXT NOT NULL,
                previous_verdict TEXT NOT NULL,
                decision TEXT NOT NULL,
                new_verdict TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit events are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit events are immutable');
            END;
            """
        )


def create_case(case: dict[str, object]) -> dict[str, object]:
    details = case["details"]
    with _connection() as connection:
        connection.execute(
            """
            INSERT INTO cases (
                id, input_type, submitted_at, verdict, risk_band, review_status,
                model_version, summary, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case["id"],
                case["input_type"],
                case["submitted_at"],
                case["verdict"],
                case["risk_band"],
                case["review_status"],
                case["model_version"],
                case["summary"],
                json.dumps(details, ensure_ascii=True),
            ),
        )
    return get_case(str(case["id"])) or {}


def _case_dict(row: sqlite3.Row, include_details: bool = False) -> dict[str, object]:
    result: dict[str, object] = {
        "id": row["id"],
        "input_type": row["input_type"],
        "submitted_at": row["submitted_at"],
        "verdict": row["verdict"],
        "risk_band": row["risk_band"],
        "review_status": row["review_status"],
        "model_version": row["model_version"],
        "summary": row["summary"],
    }
    if include_details:
        result["details"] = json.loads(row["details_json"])
    return result


def list_cases(
    limit: int = 50, offset: int = 0, verdict: str | None = None, review_status: str | None = None
) -> dict[str, object]:
    filters: list[str] = []
    values: list[object] = []
    if verdict:
        filters.append("verdict = ?")
        values.append(verdict)
    if review_status:
        filters.append("review_status = ?")
        values.append(review_status)
    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    with _connection() as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM cases {where_clause}", values
        ).fetchone()[0]
        rows = connection.execute(
            f"""
            SELECT * FROM cases {where_clause}
            ORDER BY submitted_at DESC
            LIMIT ? OFFSET ?
            """,
            [*values, limit, offset],
        ).fetchall()
    return {"items": [_case_dict(row) for row in rows], "total": total}


def get_case(case_id: str) -> dict[str, object] | None:
    with _connection() as connection:
        row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            return None
        case = _case_dict(row, include_details=True)
        timeline = connection.execute(
            """
            SELECT actor, previous_verdict, decision, new_verdict, reason, created_at
            FROM review_events WHERE case_id = ? ORDER BY created_at ASC, id ASC
            """,
            (case_id,),
        ).fetchall()
    case["timeline"] = [dict(event) for event in timeline]
    return case


def review_case(
    case_id: str, decision: str, reason: str, actor: str = "local-reviewer"
) -> dict[str, object] | None:
    from datetime import datetime, timezone

    verdict_by_decision = {
        "confirmed_phishing": "likely_phishing",
        "false_positive": "no_known_threat",
        "needs_more_evidence": "needs_review",
    }
    new_verdict = verdict_by_decision[decision]
    now = datetime.now(timezone.utc).isoformat()
    clean_reason = reason.strip()
    if len(clean_reason) < 3:
        raise ValueError("A review reason of at least 3 characters is required.")
    with _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            return None
        previous_verdict = str(row["verdict"])
        connection.execute(
            """
            INSERT INTO review_events (
                case_id, actor, previous_verdict, decision, new_verdict, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (case_id, actor, previous_verdict, decision, new_verdict, clean_reason, now),
        )
        review_status = (
            "pending" if decision == "needs_more_evidence" else "reviewed"
        )
        connection.execute(
            "UPDATE cases SET verdict = ?, review_status = ? WHERE id = ?",
            (new_verdict, review_status, case_id),
        )
        connection.execute(
            """
            INSERT INTO audit_events (
                actor, action, entity_type, entity_id, timestamp, metadata_json
            ) VALUES (?, ?, 'case', ?, ?, ?)
            """,
            (
                actor,
                "review_decision_recorded",
                case_id,
                now,
                json.dumps(
                    {
                        "previous_verdict": previous_verdict,
                        "new_verdict": new_verdict,
                        "decision": decision,
                        "reason": clean_reason,
                    },
                    ensure_ascii=True,
                ),
            ),
        )
    return get_case(case_id)


def operational_metrics() -> dict[str, object]:
    with _connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        pending = connection.execute(
            "SELECT COUNT(*) FROM cases WHERE review_status = 'pending'"
        ).fetchone()[0]
        verdict_rows = connection.execute(
            "SELECT verdict, COUNT(*) AS count FROM cases GROUP BY verdict"
        ).fetchall()
        input_rows = connection.execute(
            "SELECT input_type, COUNT(*) AS count FROM cases GROUP BY input_type"
        ).fetchall()
        recent_rows = connection.execute(
            """
            SELECT substr(submitted_at, 1, 10) AS day, COUNT(*) AS count
            FROM cases
            WHERE submitted_at >= datetime('now', '-13 days')
            GROUP BY day ORDER BY day
            """
        ).fetchall()
        review_count = connection.execute(
            "SELECT COUNT(*) FROM review_events"
        ).fetchone()[0]
    return {
        "total_scans": total,
        "pending_reviews": pending,
        "review_actions": review_count,
        "verdicts": {row["verdict"]: row["count"] for row in verdict_rows},
        "input_types": {row["input_type"]: row["count"] for row in input_rows},
        "daily_scans": [dict(row) for row in recent_rows],
    }
