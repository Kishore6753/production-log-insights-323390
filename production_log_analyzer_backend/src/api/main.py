from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.api.log_analysis import analyze_events, parse_log_bytes
from src.api.zip_utils import (
    combine_extracted_text_files,
    extract_log_files_from_zip_bytes,
    get_zip_max_total_uncompressed_bytes,
)


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


def _looks_like_zip(filename: str, content_type: Optional[str]) -> bool:
    """Heuristic zip detection: by extension or common mime types."""
    fn = (filename or "").lower()
    ct = (content_type or "").lower()
    if fn.endswith(".zip"):
        return True
    if ct in ("application/zip", "application/x-zip-compressed", "multipart/x-zip"):
        return True
    return False


# PUBLIC_INTERFACE
@app.post(
    "/api/logs/analyze",
    response_model=UploadAnalyzeResponse,
    tags=["Log Analysis"],
    summary="Upload a log file (or zip of logs) and generate a structured analysis report",
    description=(
        "Accepts a log file upload (text, JSON lines, or common log formats). "
        "Also accepts .zip archives containing log files (.log, .txt, .json, .ndjson). "
        "Returns a structured analysis report including summary statistics, issue clusters with evidence vs "
        "hypotheses, pattern detection, timeline buckets, and prioritized troubleshooting steps."
    ),
    operation_id="upload_and_analyze_logs",
)
async def upload_and_analyze_logs(
    file: UploadFile = File(
        ...,
        description=(
            "Log file to analyze (text, JSON lines, or common log formats). "
            "May also be a .zip containing .log/.txt/.json/.ndjson files."
        ),
    ),
) -> UploadAnalyzeResponse:
    """
    Upload a log file (or zip archive of log files) and generate a structured analysis report.

    Parameters:
        file: Uploaded log file, or a zip archive containing supported log files.

    Returns:
        UploadAnalyzeResponse: filename, parse warnings, and the structured analysis report.

    Raises:
        HTTPException: If the file is missing, empty, too large, or cannot be processed.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename.")

    raw = await file.read()
    if not raw or len(raw) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Soft size guard (avoid pathological uploads). 10MB default.
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 10MB).")

    parse_warnings: List[str] = []

    # If it's a zip, extract and combine supported members, then reuse existing parser.
    if _looks_like_zip(file.filename, file.content_type):
        # Zip bomb protection (configurable). This limits the total *expanded* size of all
        # allowed members (.log/.txt/.json/.ndjson) extracted from the archive.
        zip_max_uncompressed = get_zip_max_total_uncompressed_bytes()
        try:
            extracted, zip_warnings = extract_log_files_from_zip_bytes(
                raw,
                max_total_uncompressed=zip_max_uncompressed,
            )
        except ValueError as e:
            # Keep status 400, but provide clearer actionable detail.
            raise HTTPException(status_code=400, detail=str(e)) from e

        parse_warnings.extend(zip_warnings)

        if not extracted:
            # Keep response format unchanged, but return 400 for "nothing to analyze"
            # so the user gets immediate feedback rather than an empty report.
            raise HTTPException(
                status_code=400,
                detail=(
                    "Zip archive contained no supported log files to analyze. "
                    "Supported extensions: .log .txt .json .ndjson"
                ),
            )

        combined = combine_extracted_text_files(extracted)
        # Preserve the original uploaded filename in the response.
        events, parse_warnings_from_parse = parse_log_bytes(combined, filename=file.filename)
        parse_warnings.extend(parse_warnings_from_parse)
    else:
        events, parse_warnings_from_parse = parse_log_bytes(raw, filename=file.filename)
        parse_warnings.extend(parse_warnings_from_parse)

    report = analyze_events(events)

    return UploadAnalyzeResponse(
        filename=file.filename,
        content_type=file.content_type,
        parse_warnings=parse_warnings,
        report=report,
    )
