from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status

from app.core.auth import verify_api_auth
from app.core.errors import EmailIngestionError
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
    auth_token: str = Depends(verify_api_auth)
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

    # 2. Pipeline Analysis Orchestration
    analysis_run = await orchestrator.analyze_email(normalized_email)

    # 3. Signal Correlation & Deduplication
    correlation_output = correlation_engine.correlate(analysis_run)

    # 4. Risk Calculation
    analyzer_statuses = [item.status.value for item in analysis_run.analyzer_results.values()]
    risk_result = risk_engine.calculate_risk(correlation_output, analyzer_statuses=analyzer_statuses)

    # 5. Evidence-based Threat Classification
    classification = classification_engine.classify(
        risk_result=risk_result,
        correlation_output=correlation_output,
        analyzer_results=analysis_run.analyzer_results
    )

    # 6. Delivery Policy Routing Evaluation
    policy_decision = delivery_policy_engine.evaluate_policy(
        classification=classification,
        risk_result=risk_result,
        correlation_output=correlation_output
    )

    # 7. Response Construction
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
