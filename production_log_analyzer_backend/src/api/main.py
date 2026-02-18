from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.api.log_analysis import analyze_events, parse_log_bytes


class AnalysisOptions(BaseModel):
    """Options that influence parsing/analysis behavior."""

    bucket_minutes: int = Field(
        default=5,
        ge=1,
        le=60,
        description="Timeline bucket size in minutes (used when timestamps exist).",
    )


class UploadAnalyzeResponse(BaseModel):
    """Structured analysis report response."""

    filename: str = Field(..., description="Original uploaded filename.")
    content_type: Optional[str] = Field(None, description="Uploaded file content type if provided by client.")
    parse_warnings: List[str] = Field(default_factory=list, description="Any parsing warnings encountered.")
    report: Dict[str, Any] = Field(
        ...,
        description="Structured analysis report following the production-log-analysis skill standards.",
    )


openapi_tags = [
    {"name": "Health", "description": "Service health and diagnostics."},
    {"name": "Log Analysis", "description": "Upload logs and generate structured analysis reports."},
]

app = FastAPI(
    title="Production Log Analyzer API",
    description=(
        "Backend API for uploading production logs and generating a structured analysis report.\n\n"
        "Notes:\n"
        "- Evidence quotes are redacted to reduce risk of leaking sensitive data.\n"
        "- Root causes are presented as hypotheses unless directly evidenced in logs.\n"
        "- If timestamps are missing, the time window is reported as unknown."
    ),
    version="0.2.0",
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Health"], summary="Health Check")
def health_check() -> Dict[str, str]:
    """
    Health check endpoint.

    Returns:
        JSON object indicating service health.
    """
    return {"message": "Healthy"}


# PUBLIC_INTERFACE
@app.post(
    "/api/logs/analyze",
    response_model=UploadAnalyzeResponse,
    tags=["Log Analysis"],
    summary="Upload a log file and generate a structured analysis report",
    description=(
        "Accepts a log file upload (text, JSON lines, or common log formats) and returns a structured "
        "analysis report including summary statistics, issue clusters with evidence vs hypotheses, "
        "pattern detection, timeline buckets, and prioritized troubleshooting steps."
    ),
    operation_id="upload_and_analyze_logs",
)
async def upload_and_analyze_logs(
    file: UploadFile = File(..., description="Log file to analyze (text, JSON lines, or common log formats)."),
) -> UploadAnalyzeResponse:
    """
    Upload a log file and generate a structured analysis report.

    Parameters:
        file: Uploaded log file (text, JSON lines, or common log formats).

    Returns:
        UploadAnalyzeResponse: filename, parse warnings, and the structured analysis report.

    Raises:
        HTTPException: If the file is missing, empty, or cannot be processed.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename.")

    raw = await file.read()
    if not raw or len(raw) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Soft size guard (avoid pathological uploads). 10MB default.
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 10MB).")

    events, parse_warnings = parse_log_bytes(raw, filename=file.filename)
    report = analyze_events(events)

    return UploadAnalyzeResponse(
        filename=file.filename,
        content_type=file.content_type,
        parse_warnings=parse_warnings,
        report=report,
    )
