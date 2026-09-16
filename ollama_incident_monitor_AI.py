#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests


# ============================================================
# CONFIGURATION
# ============================================================

APPLICATION_DIRECTORY = Path(__file__).resolve().parent

INCIDENT_DIRECTORY = APPLICATION_DIRECTORY / "incidents"
DUMP_DIRECTORY = APPLICATION_DIRECTORY / "dump"
RESOLVED_DIRECTORY = DUMP_DIRECTORY / "resolved"
STATE_DIRECTORY = APPLICATION_DIRECTORY / "state"

INCIDENT_INDEX_FILE = STATE_DIRECTORY / "incident_index.json"
MONITOR_STATE_FILE = STATE_DIRECTORY / "monitor_state.json"
NORMALIZATION_CACHE_FILE = STATE_DIRECTORY / "normalization_cache.json"

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://localhost:11434/api/generate",
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5:3b",
)

OLLAMA_TIMEOUT = int(
    os.getenv("OLLAMA_TIMEOUT", "120")
)

POLL_INTERVAL = float(
    os.getenv("POLL_INTERVAL", "1")
)

MAX_EVENT_LINES = 100
MAX_EVENT_CHARACTERS = 30_000
MAX_RECENT_EXAMPLES = 10
MAX_NORMALIZATION_CACHE_ENTRIES = 10_000

RUNNING = True


# ============================================================
# ERROR AND WARNING DETECTION
# ============================================================

INCIDENT_START_PATTERN = re.compile(
    r"""
    (?ix)
    (?:
        \bwarning\b
        |
        \bwarn\b
        |
        \berror\b
        |
        \berr\b
        |
        \bcritical\b
        |
        \bcrit\b
        |
        \bfatal\b
        |
        \balert\b
        |
        \bemergency\b
        |
        \bemerg\b
        |
        \bpanic\b
        |
        \bexception\b
        |
        \btraceback\b
        |
        \bfailure\b
        |
        \bfailed\b
        |
        \bout[\s_-]*of[\s_-]*memory\b
        |
        \boom[\s_-]*killed\b
        |
        \bsegmentation[\s_-]*fault\b
        |
        \bconnection[\s_-]*refused\b
        |
        \bconnection[\s_-]*reset\b
        |
        \btimed?[\s_-]*out\b
        |
        \bunavailable\b
    )
    """
)


# ============================================================
# BASIC LOCAL NORMALIZATION
# ============================================================

TIMESTAMP_PATTERN = re.compile(
    r"""
    (?x)
    \b
    \d{4}-\d{2}-\d{2}
    [T\s]
    \d{2}:\d{2}:\d{2}
    (?:[.,]\d+)?
    (?:Z|[+-]\d{2}:?\d{2})?
    \b
    """
)

UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b"
)

IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

HEX_PATTERN = re.compile(
    r"\b0x[0-9a-fA-F]+\b"
)

REQUEST_ID_PATTERN = re.compile(
    r"""
    (?ix)
    \b
    (
        request[_-]?id
        |
        correlation[_-]?id
        |
        trace[_-]?id
        |
        transaction[_-]?id
        |
        session[_-]?id
    )
    \s*[:=]\s*
    ["']?[A-Za-z0-9._:/-]+["']?
    """
)

NUMBER_PATTERN = re.compile(
    r"\b\d+(?:\.\d+)?\b"
)

WHITESPACE_PATTERN = re.compile(
    r"\s+"
)


# ============================================================
# FILE UTILITIES
# ============================================================

def create_directories() -> None:
    """Create the directories required by the application."""

    for directory in (
        INCIDENT_DIRECTORY,
        DUMP_DIRECTORY,
        RESOLVED_DIRECTORY,
        STATE_DIRECTORY,
    ):
        directory.mkdir(
            parents=True,
            exist_ok=True,
        )


def utc_now() -> str:
    """Return current UTC time."""

    return datetime.now(
        timezone.utc
    ).isoformat()


def load_json(
    file_path: Path,
    default: Any,
) -> Any:
    """Read JSON data. Return the default value on failure."""

    if not file_path.exists():
        return default

    try:
        with file_path.open(
            "r",
            encoding="utf-8",
        ) as file_handle:
            return json.load(file_handle)

    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        print(
            f"[WARNING] Could not read {file_path}: {error}",
            file=sys.stderr,
        )

        return default


def atomic_write_json(
    file_path: Path,
    data: Any,
) -> None:
    """Write JSON atomically."""

    temporary_file = file_path.with_suffix(
        file_path.suffix + ".tmp"
    )

    with temporary_file.open(
        "w",
        encoding="utf-8",
    ) as file_handle:
        json.dump(
            data,
            file_handle,
            indent=4,
            ensure_ascii=False,
        )

        file_handle.flush()
        os.fsync(
            file_handle.fileno()
        )

    os.replace(
        temporary_file,
        file_path,
    )


def atomic_write_text(
    file_path: Path,
    content: str,
) -> None:
    """Write a text file atomically."""

    temporary_file = file_path.with_suffix(
        file_path.suffix + ".tmp"
    )

    with temporary_file.open(
        "w",
        encoding="utf-8",
    ) as file_handle:
        file_handle.write(content)
        file_handle.flush()
        os.fsync(
            file_handle.fileno()
        )

    os.replace(
        temporary_file,
        file_path,
    )


# ============================================================
# LOCAL FALLBACK NORMALIZATION
# ============================================================

def local_normalize(
    log_message: str,
) -> str:
    """
    Perform deterministic normalization.

    This is used:
    1. To create the Ollama normalization cache key.
    2. As a fallback if Ollama is unavailable.
    """

    normalized = log_message.lower().strip()

    normalized = TIMESTAMP_PATTERN.sub(
        "<timestamp>",
        normalized,
    )

    normalized = UUID_PATTERN.sub(
        "<uuid>",
        normalized,
    )

    normalized = IPV4_PATTERN.sub(
        "<ip>",
        normalized,
    )

    normalized = HEX_PATTERN.sub(
        "<hex>",
        normalized,
    )

    normalized = REQUEST_ID_PATTERN.sub(
        lambda match: (
            f"{match.group(1).lower()}=<id>"
        ),
        normalized,
    )

    normalized = NUMBER_PATTERN.sub(
        "<number>",
        normalized,
    )

    normalized = WHITESPACE_PATTERN.sub(
        " ",
        normalized,
    )

    return normalized.strip()


# ============================================================
# OLLAMA CLIENT
# ============================================================

class OllamaNormalizer:
    """Use a local Ollama model to normalize log events."""

    def __init__(
        self,
        url: str,
        model: str,
        timeout: int,
    ):
        self.url = url
        self.model = model
        self.timeout = timeout

    def check_connection(self) -> bool:
        """Check whether the local Ollama service is reachable."""

        try:
            response = requests.post(
                self.url,
                json={
                    "model": self.model,
                    "prompt": (
                        "Return only the word OK."
                    ),
                    "stream": False,
                    "options": {
                        "temperature": 0,
                        "num_predict": 5,
                    },
                },
                timeout=20,
            )

            response.raise_for_status()
            return True

        except requests.RequestException as error:
            print(
                f"[WARNING] Ollama connection check failed: "
                f"{error}",
                file=sys.stderr,
            )

            return False

    def normalize(
        self,
        log_message: str,
    ) -> dict[str, Any]:
        """
        Normalize the supplied warning/error log.

        Expected response:

        {
          "is_incident": true,
          "severity": "ERROR",
          "category": "database_connection",
          "component": "database",
          "normalized_signature":
              "database connection refused for host <host> port <port>",
          "summary": "Database connection was refused"
        }
        """

        prompt = f"""
You are a log normalization engine running locally on a Linux server.

Analyze the following log event.

LOG EVENT
---------
{log_message}
---------

Return only one valid JSON object.

Required JSON structure:

{{
  "is_incident": true,
  "severity": "WARNING|ERROR|CRITICAL",
  "category": "short_snake_case_category",
  "component": "affected_component_or_unknown",
  "normalized_signature": "stable normalized incident signature",
  "summary": "short human-readable summary"
}}

Normalization rules:

1. Determine whether the log represents a warning, error, exception,
   service failure, timeout, connection failure, resource problem,
   application failure or infrastructure failure.

2. Set is_incident to true for any WARNING, ERROR, CRITICAL, FATAL,
   PANIC, EXCEPTION, FAILURE, TIMEOUT or similar unhealthy event.

3. The normalized_signature is used to prevent duplicate incidents.

4. Different occurrences of the same underlying error must produce
   exactly the same normalized_signature.

5. Remove or replace dynamic values such as:
   - timestamps
   - dates
   - request IDs
   - correlation IDs
   - trace IDs
   - transaction IDs
   - UUIDs
   - process IDs
   - thread IDs
   - memory addresses
   - changing counters
   - durations
   - percentages
   - line numbers
   - ports
   - IP addresses
   - hostnames
   - container IDs
   - pod suffixes
   - instance IDs

6. Preserve information that identifies the underlying problem:
   - exception class
   - service name
   - operation name
   - HTTP status family
   - failure reason
   - affected component
   - resource type

7. Use placeholders such as:
   <timestamp>, <id>, <ip>, <host>, <port>, <number>,
   <duration>, <percentage>, <path>, <instance>, <container>.

8. Do not include the original timestamp in normalized_signature.

9. Do not include explanations outside the JSON object.

10. Do not suggest troubleshooting or remediation.

11. Use lowercase text for normalized_signature and category.

12. If the event is ambiguous but contains warning or error language,
    treat it as an incident.

Return only JSON.
"""

        response = requests.post(
            self.url,
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0,
                    "seed": 42,
                    "num_predict": 500,
                },
            },
            timeout=self.timeout,
        )

        response.raise_for_status()

        response_body = response.json()

        model_output = response_body.get(
            "response",
            "",
        ).strip()

        if not model_output:
            raise ValueError(
                "Ollama returned an empty response"
            )

        result = self._parse_json(
            model_output
        )

        return self._validate_result(
            result=result,
            original_message=log_message,
        )

    @staticmethod
    def _parse_json(
        model_output: str,
    ) -> dict[str, Any]:
        """Parse JSON returned by Ollama."""

        cleaned_output = re.sub(
            r"^```(?:json)?\s*|\s*```$",
            "",
            model_output,
            flags=re.IGNORECASE | re.DOTALL,
        )

        try:
            return json.loads(
                cleaned_output
            )

        except json.JSONDecodeError:
            json_match = re.search(
                r"\{.*\}",
                cleaned_output,
                flags=re.DOTALL,
            )

            if not json_match:
                raise ValueError(
                    "Ollama did not return a valid JSON object"
                )

            return json.loads(
                json_match.group(0)
            )

    @staticmethod
    def _validate_result(
        result: dict[str, Any],
        original_message: str,
    ) -> dict[str, Any]:
        """Validate and sanitize the model result."""

        if not isinstance(result, dict):
            raise ValueError(
                "Ollama normalization result is not an object"
            )

        signature = str(
            result.get(
                "normalized_signature",
                "",
            )
        ).strip().lower()

        if not signature:
            signature = local_normalize(
                original_message
            )

        signature = WHITESPACE_PATTERN.sub(
            " ",
            signature,
        ).strip()

        severity = str(
            result.get(
                "severity",
                "ERROR",
            )
        ).strip().upper()

        if severity not in {
            "WARNING",
            "ERROR",
            "CRITICAL",
        }:
            severity = "ERROR"

        category = str(
            result.get(
                "category",
                "unclassified_incident",
            )
        ).strip().lower()

        category = re.sub(
            r"[^a-z0-9_]+",
            "_",
            category,
        ).strip("_")

        component = str(
            result.get(
                "component",
                "unknown",
            )
        ).strip().lower()

        summary = str(
            result.get(
                "summary",
                "Warning or error detected",
            )
        ).strip()

        is_incident = result.get(
            "is_incident",
            True,
        )

        if not isinstance(
            is_incident,
            bool,
        ):
            is_incident = str(
                is_incident
            ).strip().lower() == "true"

        return {
            "is_incident": is_incident,
            "severity": severity,
            "category": (
                category
                or "unclassified_incident"
            ),
            "component": (
                component
                or "unknown"
            ),
            "normalized_signature": signature,
            "summary": summary,
            "normalization_method": "ollama",
        }


# ============================================================
# NORMALIZATION CACHE
# ============================================================

def normalization_cache_key(
    log_message: str,
) -> str:
    """
    Create a deterministic key before sending the message to Ollama.

    Repeated identical or locally normalized messages do not need another
    Ollama request.
    """

    locally_normalized = local_normalize(
        log_message
    )

    return hashlib.sha256(
        locally_normalized.encode("utf-8")
    ).hexdigest()


def get_cached_normalization(
    cache_key: str,
) -> Optional[dict[str, Any]]:
    """Return a cached normalization result."""

    cache = load_json(
        NORMALIZATION_CACHE_FILE,
        {},
    )

    cached_result = cache.get(
        cache_key
    )

    if not cached_result:
        return None

    cached_result[
        "normalization_method"
    ] = "ollama_cache"

    return cached_result


def save_normalization_cache(
    cache_key: str,
    normalized_result: dict[str, Any],
) -> None:
    """Save the Ollama normalization result."""

    cache = load_json(
        NORMALIZATION_CACHE_FILE,
        {},
    )

    cache[cache_key] = {
        **normalized_result,
        "cached_at": utc_now(),
    }

    if len(cache) > MAX_NORMALIZATION_CACHE_ENTRIES:
        sorted_entries = sorted(
            cache.items(),
            key=lambda item: item[1].get(
                "cached_at",
                "",
            ),
        )

        entries_to_remove = (
            len(cache)
            - MAX_NORMALIZATION_CACHE_ENTRIES
        )

        for key, _ in sorted_entries[
            :entries_to_remove
        ]:
            cache.pop(
                key,
                None,
            )

    atomic_write_json(
        NORMALIZATION_CACHE_FILE,
        cache,
    )


def normalize_with_ollama(
    normalizer: OllamaNormalizer,
    log_message: str,
) -> dict[str, Any]:
    """
    Normalize with cache, Ollama and deterministic fallback.

    The monitor must not lose an incident only because Ollama is temporarily
    unavailable.
    """

    cache_key = normalization_cache_key(
        log_message
    )

    cached_result = get_cached_normalization(
        cache_key
    )

    if cached_result:
        return cached_result

    try:
        normalized_result = normalizer.normalize(
            log_message
        )

        save_normalization_cache(
            cache_key=cache_key,
            normalized_result=normalized_result,
        )

        return normalized_result

    except (
        requests.RequestException,
        ValueError,
        KeyError,
        TypeError,
    ) as error:
        print(
            f"[WARNING] Ollama normalization failed: {error}",
            file=sys.stderr,
        )

        print(
            "[WARNING] Using deterministic fallback normalization.",
            file=sys.stderr,
        )

        return {
            "is_incident": True,
            "severity": detect_local_severity(
                log_message
            ),
            "category": "fallback_normalization",
            "component": "unknown",
            "normalized_signature": local_normalize(
                log_message
            ),
            "summary": (
                "Warning or error detected while Ollama "
                "normalization was unavailable"
            ),
            "normalization_method": "local_fallback",
        }


# ============================================================
# LOCAL SEVERITY FALLBACK
# ============================================================

def detect_local_severity(
    message: str,
) -> str:
    """Determine severity if Ollama is unavailable."""

    lower_message = message.lower()

    critical_terms = (
        "critical",
        "fatal",
        "panic",
        "emergency",
        "out of memory",
        "oom killed",
        "segmentation fault",
    )

    warning_terms = (
        "warning",
        "warn",
    )

    if any(
        term in lower_message
        for term in critical_terms
    ):
        return "CRITICAL"

    if any(
        term in lower_message
        for term in warning_terms
    ):
        return "WARNING"

    return "ERROR"


# ============================================================
# INCIDENT FILE MANAGEMENT
# ============================================================

def create_incident_fingerprint(
    normalized_result: dict[str, Any],
) -> str:
    """
    Create the final incident fingerprint.

    Category, component and signature are used so unrelated errors are less
    likely to be merged.
    """

    fingerprint_source = "|".join(
        [
            normalized_result.get(
                "category",
                "unknown",
            ).lower(),
            normalized_result.get(
                "component",
                "unknown",
            ).lower(),
            normalized_result.get(
                "normalized_signature",
                "",
            ).lower(),
        ]
    )

    return hashlib.sha256(
        fingerprint_source.encode("utf-8")
    ).hexdigest()


def generate_incident_id(
    fingerprint: str,
) -> str:
    """Generate a readable unique incident ID."""

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d%H%M%S")

    return (
        f"INC-{timestamp}-"
        f"{fingerprint[:8].upper()}"
    )


def active_incident_file(
    incident_id: str,
) -> Path:
    """Return the active incident-file path."""

    return (
        INCIDENT_DIRECTORY
        / f"{incident_id}.txt"
    )


def incident_as_text(
    incident: dict[str, Any],
) -> str:
    """Convert incident data into a readable text format."""

    examples = incident.get(
        "recent_examples",
        [],
    )

    formatted_examples = "\n\n".join(
        (
            f"Example {index}\n"
            f"---------\n"
            f"{example}"
        )
        for index, example in enumerate(
            examples,
            start=1,
        )
    )

    if not formatted_examples:
        formatted_examples = (
            "No examples available."
        )

    return f"""INCIDENT INFORMATION
====================

Incident ID          : {incident["incident_id"]}
Status               : {incident["status"]}
Severity             : {incident["severity"]}
Category             : {incident["category"]}
Component            : {incident["component"]}
Occurrence Count     : {incident["occurrence_count"]}
First Seen UTC       : {incident["first_seen"]}
Last Seen UTC        : {incident["last_seen"]}
Source Log           : {incident["source_log"]}
Fingerprint          : {incident["fingerprint"]}
Normalization Method : {incident["normalization_method"]}

SUMMARY
=======

{incident["summary"]}

NORMALIZED SIGNATURE
====================

{incident["normalized_signature"]}

FIRST LOG EVENT
===============

{incident["first_original_message"]}

LATEST LOG EVENT
================

{incident["latest_original_message"]}

RECENT EXAMPLES
===============

{formatted_examples}
"""


def write_incident_file(
    incident: dict[str, Any],
) -> Path:
    """Create or update the active incident text file."""

    incident_file = active_incident_file(
        incident["incident_id"]
    )

    atomic_write_text(
        incident_file,
        incident_as_text(incident),
    )

    return incident_file


def register_incident(
    source_log: Path,
    original_message: str,
    normalized_result: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    """
    Create a new incident or update an existing incident.

    Returns:
        incident_data
        is_new_incident
    """

    fingerprint = create_incident_fingerprint(
        normalized_result
    )

    incident_index = load_json(
        INCIDENT_INDEX_FILE,
        {},
    )

    now = utc_now()

    active_incident = incident_index.get(
        fingerprint
    )

    if (
        active_incident
        and active_incident.get("status") == "OPEN"
    ):
        active_incident[
            "occurrence_count"
        ] += 1

        active_incident[
            "last_seen"
        ] = now

        active_incident[
            "latest_original_message"
        ] = original_message

        current_severity = active_incident.get(
            "severity",
            "WARNING",
        )

        new_severity = normalized_result.get(
            "severity",
            "ERROR",
        )

        active_incident["severity"] = (
            highest_severity(
                current_severity,
                new_severity,
            )
        )

        examples = active_incident.setdefault(
            "recent_examples",
            [],
        )

        if (
            not examples
            or examples[-1] != original_message
        ):
            examples.append(
                original_message
            )

        active_incident[
            "recent_examples"
        ] = examples[
            -MAX_RECENT_EXAMPLES:
        ]

        incident_index[
            fingerprint
        ] = active_incident

        atomic_write_json(
            INCIDENT_INDEX_FILE,
            incident_index,
        )

        write_incident_file(
            active_incident
        )

        return active_incident, False

    incident_id = generate_incident_id(
        fingerprint
    )

    incident = {
        "incident_id": incident_id,
        "status": "OPEN",
        "severity": normalized_result[
            "severity"
        ],
        "category": normalized_result[
            "category"
        ],
        "component": normalized_result[
            "component"
        ],
        "summary": normalized_result[
            "summary"
        ],
        "normalized_signature": normalized_result[
            "normalized_signature"
        ],
        "normalization_method": normalized_result[
            "normalization_method"
        ],
        "fingerprint": fingerprint,
        "occurrence_count": 1,
        "first_seen": now,
        "last_seen": now,
        "source_log": str(
            source_log
        ),
        "first_original_message": original_message,
        "latest_original_message": original_message,
        "recent_examples": [
            original_message
        ],
    }

    incident_index[
        fingerprint
    ] = incident

    atomic_write_json(
        INCIDENT_INDEX_FILE,
        incident_index,
    )

    write_incident_file(
        incident
    )

    return incident, True


def highest_severity(
    severity_one: str,
    severity_two: str,
) -> str:
    """Return the highest of two severity values."""

    severity_order = {
        "WARNING": 1,
        "ERROR": 2,
        "CRITICAL": 3,
    }

    if severity_order.get(
        severity_two,
        0,
    ) > severity_order.get(
        severity_one,
        0,
    ):
        return severity_two

    return severity_one


# ============================================================
# LLM RESOLUTION ARCHIVAL
# ============================================================

def resolve_incident(
    incident_id: str,
    resolution_summary: str,
    llm_rca_report: Optional[str] = None,
) -> Path:
    """
    Archive a resolved incident and remove the active text file.

    This function should be called by the later LLM RCA workflow only after
    the resolution has been validated.
    """

    incident_index = load_json(
        INCIDENT_INDEX_FILE,
        {},
    )

    selected_fingerprint = None
    selected_incident = None

    for fingerprint, incident in incident_index.items():
        if incident.get(
            "incident_id"
        ) == incident_id:
            selected_fingerprint = fingerprint
            selected_incident = incident
            break

    if (
        selected_fingerprint is None
        or selected_incident is None
    ):
        raise ValueError(
            f"Incident not found: {incident_id}"
        )

    if selected_incident.get(
        "status"
    ) == "RESOLVED":
        archived_file = selected_incident.get(
            "archived_file"
        )

        if archived_file:
            return Path(
                archived_file
            )

        raise ValueError(
            f"Incident is already resolved: {incident_id}"
        )

    incident_file = active_incident_file(
        incident_id
    )

    if not incident_file.exists():
        raise FileNotFoundError(
            f"Active incident file was not found: "
            f"{incident_file}"
        )

    resolved_at = utc_now()

    archive_timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    archive_file = (
        RESOLVED_DIRECTORY
        / (
            f"{incident_id}_resolved_"
            f"{archive_timestamp}.txt"
        )
    )

    original_incident_content = (
        incident_file.read_text(
            encoding="utf-8"
        )
    )

    resolved_content = f"""{original_incident_content}

RESOLUTION
==========

Resolved At UTC:
{resolved_at}

Resolution Summary:
{resolution_summary.strip()}
"""

    if llm_rca_report:
        resolved_content += f"""

LLM RCA REPORT
==============

{llm_rca_report.strip()}
"""

    atomic_write_text(
        archive_file,
        resolved_content,
    )

    if not archive_file.exists():
        raise OSError(
            "Resolved incident archive was not created"
        )

    if archive_file.stat().st_size == 0:
        archive_file.unlink(
            missing_ok=True
        )

        raise OSError(
            "Resolved incident archive is empty. "
            "The active incident was not removed."
        )

    selected_incident[
        "status"
    ] = "RESOLVED"

    selected_incident[
        "resolved_at"
    ] = resolved_at

    selected_incident[
        "resolution_summary"
    ] = resolution_summary.strip()

    selected_incident[
        "archived_file"
    ] = 
