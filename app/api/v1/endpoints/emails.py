from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import verify_api_auth
from app.core.errors import EmailIngestionError
from app.db.database import get_db
from app.models.email import Email
from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.decision_repository import DecisionRepository
from app.repositories.email_repository import EmailRepository
from app.repositories.forensic_repository import ForensicRepository
from app.repositories.ml_repository import MLRepository
from app.repositories.security_repository import SecurityRepository
from app.schemas.analysis import EmailAnalysisRequest, EmailAnalysisResponse
from app.services.analysis_orchestrator import AnalysisOrchestrator
from app.services.classification_engine import ClassificationEngine
from app.services.correlation_engine import CorrelationEngine
from app.services.delivery_policy import DeliveryPolicyEngine
from app.services.email_ingestion import EmailIngestionService
from app.services.risk_engine import RiskEngine

router = APIRouter()

# Service instances for pipeline orchestration
ingestion_service = EmailIngestionService()
orchestrator = AnalysisOrchestrator()
correlation_engine = CorrelationEngine()
risk_engine = RiskEngine()
classification_engine = ClassificationEngine()
delivery_policy_engine = DeliveryPolicyEngine()


def serialize_email(email: Email, db: Session) -> Dict[str, Any]:
    """Serializes an Email database entity into normalized frontend/API representation."""
    analysis_repo = AnalysisRepository(db)
    decision_repo = DecisionRepository(db)
    security_repo = SecurityRepository(db)

    analysis_run = analysis_repo.get_latest_for_email(email.id)
    decision = decision_repo.get_latest_decision_for_email(email.id)
    tags = security_repo.get_tags_for_email(email.id)

    recipient = ""
    if email.recipients:
        first_rec = email.recipients[0]
        if isinstance(first_rec, dict):
            recipient = first_rec.get("address", "")
        else:
            recipient = str(first_rec)

    risk_score = 0.0
    threat_confidence = 0.0
    classification = "UNKNOWN"
    if analysis_run:
        if analysis_run.overall_risk_score is not None:
            risk_score = float(analysis_run.overall_risk_score)
        if analysis_run.threat_confidence is not None:
            threat_confidence = float(analysis_run.threat_confidence)
        if analysis_run.classification:
            classification = analysis_run.classification.upper()
    elif decision:
        if decision.risk_score is not None:
            risk_score = float(decision.risk_score)
        if decision.classification:
            classification = decision.classification.upper()

    action = (decision.action if decision and decision.action else "INBOX").upper()

    tag_names = [t.name for t in tags] if tags else (
        [t.name for t in analysis_run.tags] if (analysis_run and hasattr(analysis_run, "tags") and analysis_run.tags) else []
    )

    display_time = email.received_at.strftime("%I:%M %p") if email.received_at else ""
    iso_time = email.received_at.isoformat() if email.received_at else None

    # Parse auth results from headers if available
    auth_results = {}
    if email.headers and isinstance(email.headers, dict):
        auth_header = email.headers.get("authentication-results") or email.headers.get("Authentication-Results") or ""
        if isinstance(auth_header, str) and auth_header:
            auth_lower = auth_header.lower()
            auth_results = {
                "spf": "PASS" if "spf=pass" in auth_lower else ("FAIL" if "spf=fail" in auth_lower else "NONE"),
                "dkim": "PASS" if "dkim=pass" in auth_lower else ("FAIL" if "dkim=fail" in auth_lower else "NONE"),
                "dmarc": "PASS" if "dmarc=pass" in auth_lower else ("FAIL" if "dmarc=fail" in auth_lower else "NONE"),
            }
        elif isinstance(auth_header, dict):
            auth_results = auth_header

    category = None
    if decision:
        category = decision.spam_category or decision.gateway_category

    return {
        "id": email.id,
        "emailId": email.id,
        "message_id": email.message_id,
        "messageId": email.message_id,
        "subject": email.subject or "",
        "sender": email.sender_address,
        "senderName": email.sender_name or email.sender_address,
        "recipient": recipient,
        "recipients": email.recipients or [],
        "timestamp": iso_time,
        "displayTime": display_time,
        "classification": classification,
        "action": action,
        "unread": True,
        "riskScore": int(risk_score),
        "risk_score": risk_score,
        "confidence": threat_confidence,
        "threat_confidence": threat_confidence,
        "tags": tag_names,
        "provenance": "VERIFIED_EVIDENCE",
        "bodyHtml": f"<p>{email.body_text_preview or ''}</p>",
        "body_text_preview": email.body_text_preview or "",
        "attachments": email.attachment_metadata or [],
        "urls": email.urls or [],
        "authResults": auth_results,
        "category": category,
        "headers": email.headers or {},
        "raw_size_bytes": len((email.body_text_preview or "").encode("utf-8")),
        "mailbox_id": email.mailbox_id,
        "user_id": email.user_id,
    }


@router.post(
    "/analyze",
    response_model=EmailAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit an email for pre-delivery security analysis",
    description="Ingests, normalizes, orchestrates analyzers, correlates signals, calculates risk, classifies threat, and evaluates delivery policy."
)
async def analyze_email_endpoint(
    payload: EmailAnalysisRequest,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> EmailAnalysisResponse:
    """Protected email gateway analysis endpoint."""
    # 1. Ingestion & Normalization
    if payload.raw_email:
        normalized_email = ingestion_service.parse_raw_email(
            raw_content=payload.raw_email,
            message_id_override=payload.message_id
        )
    else:
        req_dict = payload.model_dump(exclude_unset=True)
        if not any(req_dict.values()):
            raise EmailIngestionError("Empty analysis request payload")
        normalized_email = ingestion_service.parse_dict(req_dict)

    # 2. Email Persistence (M2 Step 2)
    email_repo = EmailRepository(db)
    email_db = email_repo.get_by_message_id(normalized_email.message_id)
    if not email_db:
        email_db = email_repo.create(
            message_id=normalized_email.message_id,
            sender_address=normalized_email.sender.address,
            sender_name=normalized_email.sender.name,
            received_at=normalized_email.timestamp,
            recipients=[r.model_dump(mode="json") for r in normalized_email.recipients],
            reply_to=[r.model_dump(mode="json") for r in normalized_email.reply_to] if normalized_email.reply_to else None,
            subject=normalized_email.subject,
            headers=normalized_email.headers,
            body_text_preview=normalized_email.body_text_preview,
            attachment_metadata=[a.model_dump(mode="json") for a in normalized_email.attachments],
            urls=[u.model_dump(mode="json") for u in normalized_email.urls],
            received_hops=[h.model_dump(mode="json") for h in normalized_email.received_hops],
            mailbox_id=normalized_email.mailbox_id,
            user_id=normalized_email.user_id,
        )

    # 3. Pipeline Analysis Orchestration
    analysis_run = await orchestrator.analyze_email(normalized_email)

    # 4. AnalysisRun Persistence (M2 Step 3)
    analysis_repo = AnalysisRepository(db)
    analysis_db = analysis_repo.create(
        email_id=email_db.id,
        analysis_id=analysis_run.analysis_id,
        status=analysis_run.status.value if hasattr(analysis_run.status, "value") else str(analysis_run.status),
        analyzer_results={k: v.model_dump(mode="json") for k, v in analysis_run.analyzer_results.items()},
        canonical_features=analysis_run.canonical_features.model_dump(mode="json") if analysis_run.canonical_features else None,
        errors=analysis_run.errors,
        started_at=analysis_run.created_at,
        completed_at=analysis_run.completed_at,
    )

    # 5. Signal Correlation & Deduplication
    correlation_output = correlation_engine.correlate(analysis_run)

    # 6. Security Findings & Security Tags Persistence (M2 Step 4)
    security_repo = SecurityRepository(db)
    for finding in correlation_output.deduplicated_findings:
        sev_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        security_repo.create_finding(
            analysis_id=analysis_db.id,
            email_id=email_db.id,
            code=finding.code,
            severity=sev_str,
            description=finding.description,
            details=finding.details if isinstance(finding.details, dict) else {},
        )

    if correlation_output.security_tags:
        security_repo.attach_tags_to_analysis(
            analysis_id=analysis_db.id,
            tag_names=correlation_output.security_tags,
        )

    # 7. Risk Calculation
    analyzer_statuses = [item.status.value for item in analysis_run.analyzer_results.values()]
    risk_result = risk_engine.calculate_risk(correlation_output, analyzer_statuses=analyzer_statuses)

    # 8. Evidence-based Threat Classification
    classification = classification_engine.classify(
        risk_result=risk_result,
        correlation_output=correlation_output,
        analyzer_results=analysis_run.analyzer_results
    )

    # 9. Delivery Policy Routing Evaluation
    policy_decision = delivery_policy_engine.evaluate_policy(
        classification=classification,
        risk_result=risk_result,
        correlation_output=correlation_output
    )

    # 10. PolicyDecision & DeliveryEvent Persistence (M2 Step 5)
    decision_repo = DecisionRepository(db)
    policy_decision_db = decision_repo.create_policy_decision(
        analysis_id=analysis_db.id,
        email_id=email_db.id,
        classification=classification.value if hasattr(classification, "value") else str(classification),
        action=policy_decision.action.value if hasattr(policy_decision.action, "value") else str(policy_decision.action),
        risk_level=risk_result.risk_level.value if hasattr(risk_result.risk_level, "value") else str(risk_result.risk_level),
        risk_score=risk_result.overall_risk_score,
        reason=policy_decision.reason,
        spam_category=policy_decision.spam_category.value if hasattr(policy_decision.spam_category, "value") and policy_decision.spam_category else (str(policy_decision.spam_category) if policy_decision.spam_category else None),
        gateway_category=policy_decision.gateway_category.value if hasattr(policy_decision.gateway_category, "value") and policy_decision.gateway_category else (str(policy_decision.gateway_category) if policy_decision.gateway_category else None),
        policy_version=policy_decision.policy_version,
    )

    decision_repo.create_delivery_event(
        email_id=email_db.id,
        action=policy_decision.action.value if hasattr(policy_decision.action, "value") else str(policy_decision.action),
        status="COMPLETED",
        policy_decision_id=policy_decision_db.id,
        reason=policy_decision.reason,
        details={
            "classification": classification.value if hasattr(classification, "value") else str(classification),
            "risk_score": risk_result.overall_risk_score,
            "risk_level": risk_result.risk_level.value if hasattr(risk_result.risk_level, "value") else str(risk_result.risk_level),
        },
    )


    # 11. Final AnalysisRun Verdict Persistence Update
    classification_str = classification.value if hasattr(classification, "value") else str(classification)
    risk_level_str = risk_result.risk_level.value if hasattr(risk_result.risk_level, "value") else str(risk_result.risk_level)
    analysis_repo.update_status_result(
        analysis_id=analysis_db.id,
        status=analysis_run.status.value if hasattr(analysis_run.status, "value") else str(analysis_run.status),
        overall_risk_score=risk_result.overall_risk_score,
        risk_level=risk_level_str,
        threat_confidence=risk_result.threat_confidence,
        classification=classification_str,
        completed_at=datetime.now(timezone.utc),
    )

    # 12. ML Result Persistence
    ml_item = analysis_run.analyzer_results.get("ml")
    if ml_item:
        ml_repo = MLRepository(db)
        ml_features = ml_item.features or {}
        ml_status = ml_item.status.value if hasattr(ml_item.status, "value") else str(ml_item.status)
        ml_repo.create(
            analysis_id=analysis_db.id,
            email_id=email_db.id,
            model_name=str(ml_features.get("model_name", "intent_classifier_tfidf_nb")),
            model_version=str(ml_features.get("model_version", "1.0.0")),
            status=ml_status,
            prediction=str(ml_features.get("prediction")) if ml_features.get("prediction") is not None else None,
            confidence=float(ml_features.get("confidence")) if ml_features.get("confidence") is not None else None,
            scores=ml_features.get("probabilities", {}),
            features_used=["content_nlp", "bec_impersonation", "behavioral"],
            inference_time_ms=ml_item.execution_time_ms,
            error_message=ml_item.error_message,
        )

    # 13. Evidence & Forensic Case Persistence
    forensic_item = analysis_run.analyzer_results.get("forensic")
    forensic_repo = ForensicRepository(db)
    evidence_db = None
    if forensic_item and forensic_item.features:
        f_feat = forensic_item.features
        raw_sha256 = f_feat.get("raw_sha256")
        if raw_sha256:
            evidence_db = forensic_repo.create_evidence(
                email_id=email_db.id,
                analysis_id=analysis_db.id,
                evidence_type="EMAIL_PAYLOAD",
                sha256_hash=raw_sha256,
                source_metadata={
                    "message_id": normalized_email.message_id,
                    "subject": normalized_email.subject,
                },
                extracted_facts=f_feat.get("extracted_facts", {}),
            )

    action_str = policy_decision.action.value if hasattr(policy_decision.action, "value") else str(policy_decision.action)
    if (
        classification_str in ("MALICIOUS", "PHISHING", "BEC")
        or risk_result.overall_risk_score >= 70.0
        or action_str in ("QUARANTINE", "HOLD", "REJECT")
    ):
        case_title = f"Forensic Threat Case: {normalized_email.subject or normalized_email.message_id}"
        case_db = forensic_repo.create_case(
            title=case_title[:255],
            description=(
                f"Automated threat investigation initiated. "
                f"Risk Score: {risk_result.overall_risk_score}/100. "
                f"Classification: {classification_str}. "
                f"Policy Action: {action_str}."
            ),
            status="OPEN",
            severity="CRITICAL" if risk_result.overall_risk_score >= 85.0 else "HIGH",
            tags=correlation_output.security_tags,
        )
        forensic_repo.attach_email_to_case(case_db.id, email_db.id)
        if evidence_db:
            forensic_repo.attach_evidence_to_case(case_db.id, evidence_db.id)

    # 14. Response Construction
    return EmailAnalysisResponse(
        analysis_id=analysis_run.analysis_id,
        email_id=normalized_email.message_id,
        risk=risk_result,
        classification=classification_str,
        decision=policy_decision,
        analyzer_results=analysis_run.analyzer_results,
        findings=correlation_output.deduplicated_findings,
        tags=correlation_output.security_tags,
        timestamp=datetime.now(timezone.utc),
    )


@router.get(
    "",
    summary="List received emails with optional filters",
)
async def list_emails_endpoint(
    action: Optional[str] = Query(None, description="Filter by delivery action (e.g. INBOX, SPAM, QUARANTINE)"),
    classification: Optional[str] = Query(None, description="Filter by threat classification (e.g. SAFE, PHISHING, SPAM)"),
    category: Optional[str] = Query(None, description="Filter by category (e.g. Marketing, Scam)"),
    search: Optional[str] = Query(None, description="Search term in subject or sender"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
):
    email_repo = EmailRepository(db)
    emails = email_repo.query_filtered(
        action=action,
        classification=classification,
        category=category,
        search=search,
        limit=limit,
        offset=offset,
    )
    return [serialize_email(e, db) for e in emails]


@router.get(
    "/{email_id}",
    summary="Retrieve single email by ID or RFC 5322 Message-ID",
)
async def get_email_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
):
    email_repo = EmailRepository(db)
    email = email_repo.get_by_identifier(email_id)
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' not found")
    return serialize_email(email, db)


@router.get(
    "/{email_id}/findings",
    summary="Retrieve security findings for an email",
)
async def get_email_findings_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
):
    email_repo = EmailRepository(db)
    email = email_repo.get_by_identifier(email_id)
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' not found")

    security_repo = SecurityRepository(db)
    decision_repo = DecisionRepository(db)
    findings = security_repo.get_findings_for_email(email.id)
    decision = decision_repo.get_latest_decision_for_email(email.id)

    serialized_findings = [
        {
            "id": f.id,
            "code": f.code,
            "severity": f.severity,
            "description": f.description,
            "details": f.details or {},
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]

    serialized_email = serialize_email(email, db)

    return {
        "email_id": email.id,
        "emailId": email.id,
        "findings": serialized_findings,
        "authResults": serialized_email["authResults"],
        "urlFindings": [f for f in serialized_findings if "URL" in f["code"]],
        "attachmentFindings": [f for f in serialized_findings if "ATTACHMENT" in f["code"] or "FILE" in f["code"]],
        "warningReason": decision.reason if decision else None,
    }


@router.get(
    "/{email_id}/tags",
    summary="Retrieve security tags for an email",
)
async def get_email_tags_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
):
    email_repo = EmailRepository(db)
    email = email_repo.get_by_identifier(email_id)
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' not found")

    security_repo = SecurityRepository(db)
    tags = security_repo.get_tags_for_email(email.id)
    return {"tags": [t.name for t in tags]}


@router.get(
    "/{email_id}/risk",
    summary="Retrieve authoritative risk verdict for an email",
)
async def get_email_risk_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
):
    email_repo = EmailRepository(db)
    email = email_repo.get_by_identifier(email_id)
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' not found")

    analysis_repo = AnalysisRepository(db)
    run = analysis_repo.get_latest_for_email(email.id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No analysis run found for email '{email_id}'")

    return {
        "email_id": email.id,
        "risk_score": run.overall_risk_score if run.overall_risk_score is not None else 0.0,
        "riskScore": int(run.overall_risk_score) if run.overall_risk_score is not None else 0,
        "risk_level": run.risk_level or "LOW",
        "threat_confidence": run.threat_confidence or 0.0,
        "confidence": run.threat_confidence or 0.0,
        "classification": run.classification or "UNKNOWN",
    }


@router.get(
    "/{email_id}/decision",
    summary="Retrieve authoritative policy decision for an email",
)
async def get_email_decision_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
):
    email_repo = EmailRepository(db)
    email = email_repo.get_by_identifier(email_id)
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' not found")

    decision_repo = DecisionRepository(db)
    decision = decision_repo.get_latest_decision_for_email(email.id)
    if not decision:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No policy decision found for email '{email_id}'")

    analysis_repo = AnalysisRepository(db)
    run = analysis_repo.get_latest_for_email(email.id)

    return {
        "email_id": email.id,
        "classification": decision.classification,
        "risk_score": decision.risk_score,
        "threat_confidence": run.threat_confidence if run else 0.0,
        "action": decision.action,
        "reason": decision.reason,
        "spam_category": decision.spam_category,
        "gateway_category": decision.gateway_category,
    }


@router.get(
    "/{email_id}/ml-result",
    summary="Retrieve ML prediction result for an email",
)
async def get_email_ml_result_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
):
    email_repo = EmailRepository(db)
    email = email_repo.get_by_identifier(email_id)
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' not found")

    ml_repo = MLRepository(db)
    ml_res = ml_repo.get_latest_for_email(email.id)
    if not ml_res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No ML result found for email '{email_id}'")

    return {
        "email_id": email.id,
        "emailId": email.id,
        "prediction": ml_res.prediction,
        "confidence": ml_res.confidence,
        "model_name": ml_res.model_name,
        "model_version": ml_res.model_version,
        "modelVersion": ml_res.model_version,
        "scores": ml_res.scores or {},
        "probabilities": ml_res.scores or {},
        "features_used": ml_res.features_used or [],
        "inference_time_ms": ml_res.inference_time_ms,
        "status": ml_res.status,
        "provenance": "MODEL_PREDICTION",
    }


@router.get(
    "/{email_id}/evidence",
    summary="Retrieve cryptographic evidence for an email",
)
async def get_email_evidence_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
):
    email_repo = EmailRepository(db)
    email = email_repo.get_by_identifier(email_id)
    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' not found")

    forensic_repo = ForensicRepository(db)
    evidence_list = forensic_repo.get_evidence_for_email(email.id)

    serialized_evidence = [
        {
            "id": e.id,
            "evidence_id": e.id,
            "evidence_type": e.evidence_type,
            "sha256_hash": e.sha256_hash,
            "sha256": e.sha256_hash,
            "source_metadata": e.source_metadata or {},
            "extracted_facts": e.extracted_facts or {},
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "provenance": "VERIFIED_EVIDENCE",
        }
        for e in evidence_list
    ]

    primary_sha256 = evidence_list[0].sha256_hash if evidence_list else None

    return {
        "email_id": email.id,
        "emailId": email.id,
        "evidence": serialized_evidence,
        "sha256": primary_sha256,
        "sha256Hash": primary_sha256,
        "provenance": "VERIFIED_EVIDENCE",
    }


@router.post(
    "/{email_id}/analyze",
    response_model=EmailAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger analysis on an existing email by ID",
)
async def analyze_existing_email_endpoint(
    email_id: str,
    auth_token: str = Depends(verify_api_auth),
    db: Session = Depends(get_db),
) -> EmailAnalysisResponse:
    email_repo = EmailRepository(db)
    email_db = email_repo.get_by_identifier(email_id)
    if not email_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' not found")

    payload = EmailAnalysisRequest(
        message_id=email_db.message_id,
        sender=email_db.sender_address,
        recipients=[r.get("address", "") if isinstance(r, dict) else str(r) for r in email_db.recipients],
        subject=email_db.subject,
        body=email_db.body_text_preview or "",
        headers=email_db.headers,
    )
    return await analyze_email_endpoint(payload=payload, auth_token=auth_token, db=db)
