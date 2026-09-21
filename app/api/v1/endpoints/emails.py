from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.auth import verify_api_auth
from app.core.errors import EmailIngestionError
from app.db.database import get_db
from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.decision_repository import DecisionRepository
from app.repositories.email_repository import EmailRepository
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


    # 11. Response Construction
    return EmailAnalysisResponse(
        analysis_id=analysis_run.analysis_id,
        email_id=normalized_email.message_id,
        risk=risk_result,
        classification=classification.value,
        decision=policy_decision,
        analyzer_results=analysis_run.analyzer_results,
        findings=correlation_output.deduplicated_findings,
        tags=correlation_output.security_tags,
        timestamp=datetime.now(timezone.utc),
    )




