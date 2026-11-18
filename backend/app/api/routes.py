from fastapi import APIRouter, HTTPException, Query, Request

from backend.app import database
from backend.app.config import MAX_EMAIL_BYTES
from backend.app.schemas import EmailScanRequest, ReviewRequest, URLScanRequest
from backend.app.services.model_runtime import model_card
from backend.app.services.scanner import (
    build_case,
    evaluate_email,
    evaluate_url,
    model_version_from,
)
from backend.app.services.threat_intel import feed_status

router = APIRouter()


def _evaluate_url_case(value: str) -> dict[str, object]:
    try:
        result = evaluate_url(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    case = build_case("url", result, model_version_from(result))
    return database.create_case(case)


def _evaluate_email_case(raw: bytes) -> dict[str, object]:
    try:
        result = evaluate_email(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    versions = result["model_versions"]
    model_version = versions[0] if len(versions) == 1 else None
    case = build_case("email", result, model_version)
    return database.create_case(case)


@router.post("/scan/url")
@router.post("/scans/url")
def scan_url(payload: URLScanRequest) -> dict[str, object]:
    return {"case": _evaluate_url_case(payload.url)}


@router.post("/scan/email")
@router.post("/scans/email")
def scan_email(payload: EmailScanRequest) -> dict[str, object]:
    raw = payload.content.encode("utf-8")
    if len(raw) > MAX_EMAIL_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Email content exceeds the {MAX_EMAIL_BYTES}-byte limit.",
        )
    return {"case": _evaluate_email_case(raw)}


@router.post("/scan/email/upload")
async def scan_email_upload(request: Request) -> dict[str, object]:
    raw = await request.body()
    if not raw:
        raise HTTPException(status_code=422, detail="No email content received.")
    if len(raw) > MAX_EMAIL_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Email file exceeds the {MAX_EMAIL_BYTES}-byte limit.",
        )
    return {"case": _evaluate_email_case(raw)}


@router.get("/cases")
def get_cases(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    verdict: str | None = Query(default=None),
    review_status: str | None = Query(default=None),
) -> dict[str, object]:
    allowed_verdicts = {"likely_phishing", "needs_review", "no_known_threat"}
    allowed_review_status = {"pending", "reviewed", "not_required"}
    if verdict is not None and verdict not in allowed_verdicts:
        raise HTTPException(status_code=422, detail="Unsupported verdict filter.")
    if review_status is not None and review_status not in allowed_review_status:
        raise HTTPException(status_code=422, detail="Unsupported review status filter.")
    return database.list_cases(limit, offset, verdict, review_status)


@router.get("/cases/{case_id}")
def get_case(case_id: str) -> dict[str, object]:
    case = database.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {"case": case}


@router.post("/cases/{case_id}/review")
def review_case(case_id: str, payload: ReviewRequest) -> dict[str, object]:
    try:
        case = database.review_case(case_id, payload.decision, payload.reason)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if case is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {"case": case}


@router.get("/threat-intel")
def get_threat_intel() -> dict[str, object]:
    try:
        return feed_status()
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/model/card")
def get_model_card() -> dict[str, object]:
    try:
        return model_card()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/reports/metrics")
def get_report_metrics() -> dict[str, object]:
    try:
        card = model_card()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "operations": database.operational_metrics(),
        "model_evaluation": card["metrics"],
        "model_status": card["status"],
    }
