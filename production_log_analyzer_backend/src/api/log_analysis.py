from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple


# --- Parsing primitives -------------------------------------------------------


_SEVERITY_NORMALIZATION = {
    "fatal": "critical",
    "crit": "critical",
    "critical": "critical",
    "error": "high",
    "err": "high",
    "warning": "medium",
    "warn": "medium",
    "info": "low",
    "debug": "low",
    "trace": "low",
}

# Common timestamp patterns (intentionally permissive).
_TS_PATTERNS = [
    # 2025-01-31 12:34:56,789  | 2025-01-31T12:34:56.789Z
    re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?)"
    ),
    # 31/Jan/2025:12:34:56 +0000 (common access logs)
    re.compile(
        r"(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})"
    ),
]


def _try_parse_timestamp(raw: str) -> Optional[datetime]:
    """Best-effort parse timestamp strings into timezone-aware UTC datetimes."""
    raw = raw.strip()
    # ISO-like
    try:
        # Normalize comma to dot for fractional seconds.
        iso = raw.replace(",", ".")
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass

    # Apache-like: 31/Jan/2025:12:34:56 +0000
    try:
        dt = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _extract_timestamp_from_line(line: str) -> Optional[datetime]:
    for pat in _TS_PATTERNS:
        m = pat.search(line)
        if m:
            return _try_parse_timestamp(m.group("ts"))
    return None


def _normalize_severity(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = str(value).strip().lower()
    return _SEVERITY_NORMALIZATION.get(v, v)


def _extract_severity_from_line(line: str) -> Optional[str]:
    # Look for common tokens like "ERROR", "[WARN]", "level=error", '"level":"error"'
    m = re.search(r"\b(level|lvl|severity)\s*[:=]\s*\"?(?P<sev>[A-Za-z]+)\"?\b", line, re.I)
    if m:
        return _normalize_severity(m.group("sev"))

    m = re.search(r"\b(?P<sev>FATAL|CRITICAL|ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE)\b", line, re.I)
    if m:
        return _normalize_severity(m.group("sev"))
    return None


def _safe_json_loads(s: str) -> Optional[Dict[str, Any]]:
    try:
        val = json.loads(s)
        return val if isinstance(val, dict) else None
    except Exception:
        return None


# --- Redaction ---------------------------------------------------------------

# Minimal PII/secret redaction. The skill requires redacted quotes; we comply by masking.
_REDACTIONS: List[Tuple[re.Pattern[str], str]] = [
    # Emails
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    # IPv4
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
    # Bearer tokens / API keys-ish
    (re.compile(r"\bBearer\s+[A-Za-z0-9._\-]+\b", re.I), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"\bapi[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{8,}\b", re.I), "api_key=[REDACTED]"),
    # Password assignment
    (re.compile(r"\bpassword\s*[:=]\s*\S+\b", re.I), "password=[REDACTED]"),
]


def redact_text(text: str) -> str:
    """Redact common sensitive data patterns from text."""
    out = text
    for pat, repl in _REDACTIONS:
        out = pat.sub(repl, out)
    return out


# --- Data structures ----------------------------------------------------------


@dataclass(frozen=True)
class ParsedEvent:
    ts: Optional[datetime]
    severity: str
    message: str
    raw: str
    source: str  # "json" or "text"
    fingerprint: str


def _fingerprint(severity: str, msg: str) -> str:
    """Stable hash used for clustering similar events."""
    h = hashlib.sha256()
    # Reduce uniqueness by stripping numbers/hex to cluster repeated issues.
    normalized = re.sub(r"\b0x[0-9a-fA-F]+\b", "0x?", msg)
    normalized = re.sub(r"\b\d+\b", "?", normalized)
    normalized = normalized.lower().strip()
    h.update((severity + "\n" + normalized).encode("utf-8", errors="ignore"))
    return h.hexdigest()[:16]


def parse_log_bytes(raw_bytes: bytes, filename: str) -> Tuple[List[ParsedEvent], List[str]]:
    """
    Parse log file content (best-effort) into structured events.

    Returns (events, parse_warnings).
    """
    warnings: List[str] = []
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        # Very defensive; decode should not fail with errors="replace".
        text = str(raw_bytes)
        warnings.append("File decoding used a fallback conversion; content may be degraded.")

    lines = [ln for ln in text.splitlines() if ln.strip() != ""]
    events: List[ParsedEvent] = []

    # Strategy:
    # 1) If a line is JSON object: read timestamp/level/message fields.
    # 2) Else treat as plain text; extract timestamp/severity heuristically.
    for ln in lines:
        ln_redacted = redact_text(ln)
        js = _safe_json_loads(ln)
        if js is not None:
            sev = _normalize_severity(
                js.get("level") or js.get("severity") or js.get("lvl") or js.get("log_level")
            ) or _extract_severity_from_line(ln)
            msg = js.get("message") or js.get("msg") or js.get("event") or ln
            msg = redact_text(str(msg))
            ts = js.get("timestamp") or js.get("time") or js.get("@timestamp") or js.get("ts")
            dt = _try_parse_timestamp(str(ts)) if ts else _extract_timestamp_from_line(ln)
            severity = sev or "low"
            fp = _fingerprint(severity, msg)
            events.append(
                ParsedEvent(
                    ts=dt,
                    severity=severity,
                    message=msg,
                    raw=ln_redacted,
                    source="json",
                    fingerprint=fp,
                )
            )
        else:
            sev = _extract_severity_from_line(ln) or "low"
            dt = _extract_timestamp_from_line(ln)
            msg = redact_text(ln)
            fp = _fingerprint(sev, msg)
            events.append(
                ParsedEvent(
                    ts=dt,
                    severity=sev,
                    message=msg,
                    raw=ln_redacted,
                    source="text",
                    fingerprint=fp,
                )
            )

    if not events:
        warnings.append("No non-empty log lines found.")

    # If none have timestamps, warn (skill wants explicit time window).
    if events and all(e.ts is None for e in events):
        warnings.append("No timestamps detected; time window will be reported as 'unknown'.")

    return events, warnings


# --- Analysis ----------------------------------------------------------------


def _severity_bucket(sev: str) -> str:
    sev = _normalize_severity(sev) or "low"
    if sev == "critical":
        return "critical"
    if sev == "high":
        return "high"
    if sev == "medium":
        return "medium"
    return "low"


def compute_summary(events: List[ParsedEvent]) -> Dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for e in events:
        counts[_severity_bucket(e.severity)] += 1
    return {
        "total_events": len(events),
        "counts_by_severity": counts,
    }


def compute_time_window(events: List[ParsedEvent]) -> Dict[str, Any]:
    ts = [e.ts for e in events if e.ts is not None]
    if not ts:
        return {"start": None, "end": None, "timezone": "UTC", "note": "unknown (no timestamps detected)"}
    start = min(ts)
    end = max(ts)
    return {"start": start.isoformat(), "end": end.isoformat(), "timezone": "UTC", "note": None}


def compute_timeline(events: List[ParsedEvent], bucket_minutes: int = 5) -> List[Dict[str, Any]]:
    """
    Build a simple frequency timeline (bucketed) for errors/warnings (high/medium/critical).
    If timestamps are missing, returns empty list.
    """
    ts_events = [e for e in events if e.ts is not None]
    if not ts_events:
        return []

    # Bucket by floor(timestamp to bucket_minutes).
    def floor_bucket(dt: datetime) -> datetime:
        minute = (dt.minute // bucket_minutes) * bucket_minutes
        return dt.replace(minute=minute, second=0, microsecond=0)

    buckets: Dict[datetime, Dict[str, int]] = {}
    for e in ts_events:
        sev = _severity_bucket(e.severity)
        if sev == "low":
            continue
        b = floor_bucket(e.ts)  # type: ignore[arg-type]
        if b not in buckets:
            buckets[b] = {"critical": 0, "high": 0, "medium": 0}
        if sev in buckets[b]:
            buckets[b][sev] += 1

    out = []
    for b in sorted(buckets.keys()):
        out.append(
            {
                "bucket_start": b.isoformat(),
                "bucket_minutes": bucket_minutes,
                "counts": buckets[b],
            }
        )
    return out


def _representative_evidence(events: Iterable[ParsedEvent], max_quotes: int = 3) -> List[str]:
    quotes: List[str] = []
    for e in events:
        if len(quotes) >= max_quotes:
            break
        # Evidence quote is redacted line/message.
        quotes.append(e.raw[:500])
    return quotes


def _infer_root_cause_hypotheses(message_samples: List[str]) -> List[str]:
    """
    Best-effort heuristic hypotheses (explicitly labeled hypotheses, not facts).
    """
    joined = "\n".join(message_samples).lower()
    hypotheses: List[str] = []

    # Very common production causes.
    if "timeout" in joined or "timed out" in joined:
        hypotheses.append("Upstream dependency latency or network instability causing timeouts.")
    if "connection refused" in joined or "econnrefused" in joined:
        hypotheses.append("Target service is down, misrouted, or blocked by network policy/security group.")
    if "out of memory" in joined or "oom" in joined:
        hypotheses.append("Memory pressure leading to OOM; possible leak, insufficient limits, or load spike.")
    if "permission denied" in joined or "access denied" in joined or "forbidden" in joined:
        hypotheses.append("Authorization/permission misconfiguration or credential/role changes.")
    if "rate limit" in joined or "too many requests" in joined or "429" in joined:
        hypotheses.append("Rate limiting due to traffic spike or insufficient client-side backoff.")
    if "nullpointer" in joined or "nil pointer" in joined or "undefined is not" in joined:
        hypotheses.append("Unhandled null/None case; missing input validation or unexpected payload shape.")
    if "sql" in joined and ("deadlock" in joined or "lock wait" in joined):
        hypotheses.append("Database contention/deadlocks; consider query/index tuning and transaction scope.")
    if not hypotheses:
        hypotheses.append("Insufficient signal for a specific cause; correlate with deploys, metrics, and upstream logs.")

    # Deduplicate while preserving order.
    seen = set()
    out: List[str] = []
    for h in hypotheses:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _recommend_troubleshooting_steps(severity: str, hypotheses: List[str]) -> List[Dict[str, Any]]:
    """
    Return prioritized troubleshooting steps with explicit severity tagging.
    """
    sev = _severity_bucket(severity)
    base_priority = {"critical": 1, "high": 2, "medium": 3, "low": 4}[sev]

    steps: List[str] = []
    steps.append("Confirm current incident scope: affected endpoints/services, start time, and error rate change.")
    steps.append("Check recent changes: deployments, config flips, secret rotations, infrastructure events.")
    steps.append("Correlate with metrics: latency, saturation (CPU/mem), DB connections, queue depth, 4xx/5xx rates.")
    steps.append("Inspect upstream/downstream dependency health and network connectivity.")
    steps.append("Validate credentials/permissions and expiry for any external APIs or databases.")
    steps.append("If reproducible, capture a minimal sample request/context and add targeted logging around the failure path.")

    # Tailored steps based on hypotheses keywords.
    joined = " ".join(hypotheses).lower()
    if "timeout" in joined:
        steps.insert(1, "Inspect latency percentiles and timeouts; verify retry/backoff policies and upstream SLAs.")
    if "memory" in joined or "oom" in joined:
        steps.insert(1, "Review memory usage over time; check for leaks, large payloads, and container limits.")
    if "rate limit" in joined:
        steps.insert(1, "Review traffic spikes and client backoff; consider temporary throttling or quota increase.")
    if "permission" in joined or "authorization" in joined:
        steps.insert(1, "Audit IAM/role changes and token validity; confirm least-privilege still allows required actions.")

    return [
        {"priority": base_priority + idx, "step": s, "severity": sev}
        for idx, s in enumerate(steps[:8])
    ]


def analyze_events(events: List[ParsedEvent]) -> Dict[str, Any]:
    """
    Produce a structured analysis report with strict evidence vs hypothesis separation.
    """
    summary = compute_summary(events)
    time_window = compute_time_window(events)
    timeline = compute_timeline(events)

    # Identify "issues" by clustering non-low severities.
    non_low = [e for e in events if _severity_bucket(e.severity) != "low"]
    clusters: Dict[str, List[ParsedEvent]] = {}
    for e in non_low:
        clusters.setdefault(e.fingerprint, []).append(e)

    # Sort clusters by severity then frequency.
    def cluster_sort_key(item: Tuple[str, List[ParsedEvent]]) -> Tuple[int, int]:
        _, evs = item
        max_sev = max((_severity_bucket(e.severity) for e in evs), key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}[s])
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}[max_sev]
        return (sev_rank, -len(evs))

    sorted_clusters = sorted(clusters.items(), key=cluster_sort_key)

    issues: List[Dict[str, Any]] = []
    for fp, evs in sorted_clusters[:20]:
        sev = max((_severity_bucket(e.severity) for e in evs), key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3}[s])
        sample_msgs = [e.message for e in evs[:5]]
        evidence_quotes = _representative_evidence(evs, max_quotes=3)
        hypotheses = _infer_root_cause_hypotheses(sample_msgs)
        steps = _recommend_troubleshooting_steps(sev, hypotheses)
        first_seen = min((e.ts for e in evs if e.ts is not None), default=None)
        last_seen = max((e.ts for e in evs if e.ts is not None), default=None)

        issues.append(
            {
                "issue_id": fp,
                "severity": sev,
                "title": (sample_msgs[0][:120] if sample_msgs else "Issue"),
                "frequency": len(evs),
                "first_seen": first_seen.isoformat() if first_seen else None,
                "last_seen": last_seen.isoformat() if last_seen else None,
                "evidence": {
                    "representative_quotes_redacted": evidence_quotes,
                    "notes": "Quotes are redacted; evidence is limited to uploaded log content.",
                },
                "hypotheses": hypotheses,
                "recommended_troubleshooting_steps": steps,
            }
        )

    # Pattern detection (simple, but explicit).
    patterns: List[Dict[str, Any]] = []
    if len(non_low) == 0:
        patterns.append(
            {
                "pattern": "No non-low severity events detected",
                "confidence": "high",
                "evidence": "All parsed events were classified as low severity.",
            }
        )
    else:
        top = issues[:5]
        if top:
            patterns.append(
                {
                    "pattern": "Top recurring issues (clustered by fingerprint)",
                    "confidence": "medium",
                    "evidence": [{"issue_id": i["issue_id"], "frequency": i["frequency"], "severity": i["severity"]} for i in top],
                }
            )
        if timeline:
            patterns.append(
                {
                    "pattern": "Time-bucketed spikes (non-low severities)",
                    "confidence": "low",
                    "evidence": "Review timeline buckets for sudden increases; correlate with deploys/dependency outages.",
                }
            )

    report = {
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "time_window": time_window,
        "summary_statistics": summary,
        "issues": issues,
        "patterns": patterns,
        "timeline": timeline,
    }
    return report
