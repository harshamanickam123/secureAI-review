import asyncio
import logging
from typing import Any, Dict, List, Optional
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from app.models import Finding, ScanRequest, ScanResponse
from app.semgrep_runner import run_semgrep_scan, run_semgrep_repo_scan
from app.redact import redact_secrets
from app.groq_client import explain_findings_with_groq, independent_security_review_with_groq
from app.severity import check_severity_conflict
from app.ratelimit import check_rate_limit
import app.db as db

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secureai.main")

app = FastAPI(
    title="SecureAI Review API",
    description="AI-Powered Secure Code Review Engine combining Semgrep Static Analysis with Groq LLM explanations.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
# NOTE: Currently allowing all origins for local hackathon development.
# Tighten CORS to the specific frontend production domain (e.g. https://your-app.vercel.app) before final deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory fallback scan store in case MySQL connection is not configured or offline during local dev
_fallback_scans: Dict[int, Dict[str, Any]] = {}
_fallback_id_counter = 1


async def process_scan_pipeline(
    scan_id: int,
    code_content: str,
    language: str,
    source_type: str,
) -> None:
    """
    Background pipeline:
    1. Semgrep static analysis (real subprocess detection for snippet or git repo)
    2. Redact sensitive secrets from code copy before external API call
    3. AI pass:
       - If Semgrep found static issues: Groq explains findings, suggests fixes, assesses severity
       - If Semgrep found 0 static issues: Groq conducts an independent manual security audit
    4. Cross-check severities & mark source ("semgrep" vs "ai_only")
    5. Save enriched findings and update scan status to 'done' (or 'error')
    """
    logger.info(f"Starting scan pipeline for scan_id={scan_id} (source_type={source_type}, language={language})")
    try:
        # Step 1: Run Semgrep (repo shallow clone or temp file snippet)
        if source_type == "repo":
            semgrep_results = await asyncio.to_thread(run_semgrep_repo_scan, code_content)
            redacted_code = f"Repository URL: {code_content}\nScanned {len(semgrep_results)} security findings."
        else:
            semgrep_results = await asyncio.to_thread(run_semgrep_scan, code_content, language)
            redacted_code = redact_secrets(code_content)

        logger.info(f"Semgrep detected {len(semgrep_results)} raw findings for scan_id={scan_id}")

        final_findings: List[Dict[str, Any]] = []

        if semgrep_results:
            # Mode A: Enrich Semgrep static findings with AI explanations & remediation
            ai_enrichments = await explain_findings_with_groq(redacted_code, semgrep_results)

            for raw in semgrep_results:
                rule_id = raw["rule_id"]
                enrichment = ai_enrichments.get(rule_id, {})

                ai_severity = enrichment.get("ai_severity")
                ai_explanation = enrichment.get("ai_explanation")
                ai_fix = enrichment.get("ai_fix_suggestion")
                ai_confidence = enrichment.get("ai_confidence")

                # Check if static analysis severity conflicts with AI assessment (diff >= 2 ranks)
                has_conflict = check_severity_conflict(raw["severity"], ai_severity)

                finding_dict = {
                    "rule_id": rule_id,
                    "severity": raw["severity"],
                    "file_path": raw["file_path"],
                    "line_number": raw["line_number"],
                    "raw_message": raw["raw_message"],
                    "ai_explanation": ai_explanation,
                    "ai_fix_suggestion": ai_fix,
                    "ai_confidence": ai_confidence,
                    "severity_conflict": has_conflict,
                    "source": "semgrep",
                }
                final_findings.append(finding_dict)
        else:
            # Mode B: No static findings - execute AI independent security review pass
            logger.info(f"No Semgrep findings for scan_id={scan_id}. Running AI independent review pass.")
            ai_only_findings = await independent_security_review_with_groq(redacted_code, language)
            logger.info(f"AI independent review returned {len(ai_only_findings)} findings for scan_id={scan_id}")
            final_findings = ai_only_findings

        # Step 5: Save results to database (with memory fallback)
        try:
            db.insert_findings(scan_id, final_findings)
            db.update_scan_status(scan_id, "done")
            logger.info(f"Scan {scan_id} successfully saved to MySQL database.")
        except Exception as db_err:
            logger.warning(f"Database write failed for scan {scan_id} ({db_err}). Updating in-memory store.")
            if scan_id in _fallback_scans:
                _fallback_scans[scan_id]["status"] = "done"
                _fallback_scans[scan_id]["findings"] = final_findings

    except Exception as exc:
        logger.error(f"Error executing scan pipeline for scan_id={scan_id}: {exc}", exc_info=True)
        try:
            db.update_scan_status(scan_id, "error")
        except Exception:
            if scan_id in _fallback_scans:
                _fallback_scans[scan_id]["status"] = "error"


@app.post("/api/scan", status_code=status.HTTP_202_ACCEPTED)
async def start_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    _: None = Depends(check_rate_limit),
):
    """
    Submits code for static & AI security review.
    Returns scan_id and initial 'processing' status immediately.
    """
    global _fallback_id_counter

    if not payload.content or not payload.content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source code content cannot be empty.",
        )

    # 1. Create scan entry in MySQL or fallback
    scan_id: Optional[int] = None
    try:
        scan_id = db.create_scan(
            source_type=payload.source_type,
            source_ref=payload.content[:200],  # preview/reference
            language=payload.language,
        )
    except Exception as e:
        logger.warning(f"MySQL unavailable ({e}). Using in-memory scan store.")
        scan_id = _fallback_id_counter
        _fallback_id_counter += 1
        _fallback_scans[scan_id] = {
            "scan_id": scan_id,
            "status": "processing",
            "language": payload.language,
            "source_type": payload.source_type,
            "findings": [],
        }

    # 2. Kick off background analysis task
    background_tasks.add_task(
        process_scan_pipeline,
        scan_id=scan_id,
        code_content=payload.content,
        language=payload.language,
        source_type=payload.source_type,
    )

    return {"scan_id": scan_id, "status": "processing"}


@app.get("/api/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_result(scan_id: int):
    """
    Retrieves current status and findings for a scan (used by frontend polling).
    """
    # Try fetching from MySQL first
    try:
        scan_data = db.get_scan(scan_id)
        if scan_data:
            return scan_data
    except Exception as e:
        logger.warning(f"Could not read from MySQL ({e}). Checking in-memory store.")

    # Check fallback store
    if scan_id in _fallback_scans:
        return _fallback_scans[scan_id]

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Scan with ID {scan_id} was not found.",
    )


@app.get("/health")
def health_check():
    """Service health check."""
    return {"status": "ok", "service": "SecureAI Review Backend"}
