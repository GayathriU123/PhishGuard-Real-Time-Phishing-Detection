from datetime import datetime, timezone
from uuid import uuid4

from backend.app.services.model_runtime import predict_url
from backend.app.services.threat_intel import lookup_url
from backend.app.security.email_parser import parse_email
from ml.src.features import (
    extract_url_features,
    parse_http_url,
    redact_url,
    rule_evidence,
    url_hash,
)


def _risk_band(verdict: str, rule_points: int) -> str:
    if verdict == "likely_phishing" or rule_points >= 30:
        return "high"
    if verdict == "needs_review" or rule_points > 0:
        return "medium"
    return "low"


def evaluate_url(value: str) -> dict[str, object]:
    _, _, canonical_host = parse_http_url(value)
    features = extract_url_features(value)
    normalized_display = redact_url(value)
    model = predict_url(features)
    intelligence = lookup_url(value)
    rules = rule_evidence(features)
    rule_points = sum(int(item["points"]) for item in rules)

    if intelligence["matched"]:
        verdict = "likely_phishing"
        summary = "This exact URL appears in the local verified PhishTank feed."
    elif model["status"] == "available" and model["prediction"] == "phishing":
        verdict = "likely_phishing"
        summary = "The URL model estimates phishing risk above its validation-selected threshold."
    elif model["status"] == "available" and abs(
        float(model["score"]) - float(model["threshold"])
    ) <= 0.08:
        verdict = "needs_review"
        summary = "The model estimate is close to its decision threshold."
    elif rules or (
        model["status"] == "available" and model["prediction"] == "non_phishing"
    ):
        verdict = "needs_review" if rules else "no_known_threat"
        summary = (
            "One or more structural signals need human interpretation."
            if rules
            else "No known threat was detected; this is not a safety guarantee."
        )
    else:
        verdict = "no_known_threat"
        summary = "No known threat was detected; this is not a safety guarantee."

    evidence = list(rules)
    if model["status"] == "available":
        evidence.append(
            {
                "type": "model",
                "severity": "high" if model["prediction"] == "phishing" else "info",
                "points": 0,
                "title": "Supervised URL model",
                "description": (
                    f"Model estimate: {float(model['score']):.1%}; "
                    f"validation threshold: {float(model['threshold']):.2f}."
                ),
            }
        )
    else:
        evidence.append(
            {
                "type": "model",
                "severity": "info",
                "points": 0,
                "title": "Supervised URL model unavailable",
                "description": "No trained artifact is installed; this verdict uses only rules and feed evidence.",
            }
        )
    if intelligence["matched"]:
        evidence.append(
            {
                "type": "threat_intel",
                "severity": "high",
                "points": 0,
                "title": "PhishTank exact URL match",
                "description": "The exact normalized URL matched the installed local verified feed.",
            }
        )

    return {
        "url_display": normalized_display,
        "url_hash": url_hash(value),
        "canonical_host": canonical_host,
        "verdict": verdict,
        "risk_band": _risk_band(verdict, rule_points),
        "summary": summary,
        "model": model,
        "threat_intel": intelligence,
        "evidence": evidence,
        "features": features,
        "rule_points": rule_points,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }


def evaluate_email(raw: bytes) -> dict[str, object]:
    parsed_email = parse_email(raw)
    findings: list[dict[str, object]] = list(parsed_email["signals"])
    url_findings: list[dict[str, object]] = []
    model_versions: set[str] = set()
    for candidate in parsed_email["urls"]:
        try:
            result = evaluate_url(str(candidate))
        except ValueError:
            findings.append(
                {
                    "type": "rule",
                    "severity": "medium",
                    "points": 8,
                    "title": "Extracted URL could not be analyzed",
                    "description": "A message link was not accepted by the HTTP/HTTPS URL parser.",
                }
            )
            continue
        url_findings.append(result)
        findings.extend(result["evidence"])
        model = result["model"]
        if isinstance(model, dict) and model.get("model_version"):
            model_versions.add(str(model["model_version"]))

    phishing_link = any(
        result["verdict"] == "likely_phishing" for result in url_findings
    )
    uncertain_link = any(
        result["verdict"] == "needs_review" for result in url_findings
    )
    message_rules = parsed_email["signals"]
    if phishing_link:
        verdict = "likely_phishing"
        summary = "At least one extracted URL has a phishing signal; review the message evidence."
    elif uncertain_link or message_rules:
        verdict = "needs_review"
        summary = "Message-level signals or an uncertain URL need human review."
    else:
        verdict = "no_known_threat"
        summary = "No known threat was detected; this is not a safety guarantee."
    rule_points = sum(int(item["points"]) for item in findings)
    return {
        "verdict": verdict,
        "risk_band": _risk_band(verdict, rule_points),
        "summary": summary,
        "email": {
            "sender_domain": parsed_email["sender_domain"],
            "reply_to_domain": parsed_email["reply_to_domain"],
            "has_subject": bool(parsed_email["subject"]),
            "message_evidence": message_rules,
        },
        "urls": url_findings,
        "evidence": findings,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "model_versions": sorted(model_versions),
        "model_status": (
            "available"
            if any(
                isinstance(result["model"], dict)
                and result["model"].get("status") == "available"
                for result in url_findings
            )
            else "not_trained"
        ),
    }


def build_case(
    input_type: str, result: dict[str, object], model_version: str | None = None
) -> dict[str, object]:
    verdict = str(result["verdict"])
    return {
        "id": str(uuid4()),
        "input_type": input_type,
        "submitted_at": result["analyzed_at"],
        "verdict": verdict,
        "risk_band": result["risk_band"],
        "review_status": "pending" if verdict != "no_known_threat" else "not_required",
        "model_version": model_version,
        "summary": result["summary"],
        "details": result,
    }


def model_version_from(result: dict[str, object]) -> str | None:
    model = result.get("model")
    if isinstance(model, dict):
        version = model.get("model_version")
        return str(version) if version else None
    return None
