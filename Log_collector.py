#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_POLL_INTERVAL = 1.0

BASE_DIRECTORY = Path(__file__).resolve().parent
INCIDENT_DIRECTORY = BASE_DIRECTORY / "incidents"
DUMP_DIRECTORY = BASE_DIRECTORY / "dump"
RESOLVED_DIRECTORY = DUMP_DIRECTORY / "resolved"
STATE_DIRECTORY = BASE_DIRECTORY / "state"

MONITOR_STATE_FILE = STATE_DIRECTORY / "monitor_state.json"
INCIDENT_INDEX_FILE = STATE_DIRECTORY / "incident_index.json"

MAX_MESSAGE_LENGTH = 20_000
MAX_RECENT_CONTEXT_LINES = 20

RUNNING = True


# ============================================================
# INCIDENT DETECTION
# ============================================================

SEVERITY_PATTERN = re.compile(
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
        \bfail\b
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

WARNING_PATTERN = re.compile(
    r"(?i)\b(warning|warn)\b"
)

CRITICAL_PATTERN = re.compile(
    r"""
    (?ix)
    \b(
        critical
        |
        crit
        |
        fatal
        |
        alert
        |
        emergency
        |
        emerg
        |
        panic
        |
        out[\s_-]*of[\s_-]*memory
        |
        oom[\s_-]*killed
        |
        segmentation[\s_-]*fault
    )\b
    """
)

ERROR_PATTERN = re.compile(
    r"""
    (?ix)
    \b(
        error
        |
        err
        |
        exception
        |
        traceback
        |
        failure
        |
        failed
        |
        fail
        |
        connection[\s_-]*refused
        |
        connection[\s_-]*reset
        |
        timed?[\s_-]*out
        |
        unavailable
    )\b
    """
)


# ============================================================
# NORMALIZATION PATTERNS
# ============================================================

TIMESTAMP_PATTERNS = [
    re.compile(
        r"\b\d{4}-\d{2}-\d{2}[T\s]"
        r"\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
        r"(?:Z|[+-]\d{2}:?\d{2})?\b"
    ),
    re.compile(
        r"\b\d{2}/\d{2}/\d{4}\s+"
        r"\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"
    ),
    re.compile(
        r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+"
        r"\d{2}:\d{2}:\d{2}\b"
    ),
    re.compile(
        r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"
    ),
]

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

IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

URL_PATTERN = re.compile(
    r"\bhttps?://[^\s\"']+",
    re.IGNORECASE
)

FILE_LINE_PATTERN = re.compile(
    r"(?P<file>(?:/[\w.\-]+)+):(?P<line>\d+)"
)

HEX_ADDRESS_PATTERN = re.compile(
    r"\b0x[0-9a-fA-F]+\b"
)

REQUEST_ID_PATTERN = re.compile(
    r"""
    (?ix)
    \b(
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

PID_PATTERN = re.compile(
    r"""
    (?ix)
    \b(
        pid
        |
        process[_-]?id
        |
        thread[_-]?id
        |
        tid
    )
    \s*[:=]\s*
    \d+
    """
)

PORT_PATTERN = re.compile(
    r"(?i)\bport\s*[:=]?\s*\d{1,5}\b"
)

LONG_HEX_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{16,}\b"
)

QUOTED_NUMBER_PATTERN = re.compile(
    r"""(["'])\d+(?:\.\d+)?\1"""
)

NUMBER_PATTERN = re.compile(
    r"\b\d+(?:\.\d+)?\b"
)

WHITESPACE_PATTERN = re.compile(
    r"\s+"
)


# ============================================================
# FILE AND JSON UTILITIES
# ============================================================

def utc_now() -> str:
    """Return the current UTC time in ISO 8601 format."""

    return datetime.now(timezone.utc).isoformat()


def create_directories() -> None:
    """Create all application directories."""

    for directory in (
        INCIDENT_DIRECTORY,
        DUMP_DIRECTORY,
        RESOLVED_DIRECTORY,
        STATE_DIRECTORY,
    ):
        directory.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default):
    """Load JSON safely. Return default if the file does not exist."""

    if not path.exists():
        return default

    try:
        with path.open("r", encoding="utf-8") as file_handle:
            return json.load(file_handle)
    except (json.JSONDecodeError, OSError) as error:
        print(
            f"[WARNING] Could not read state file {path}: {error}",
            file=sys.stderr,
        )
        return default


def atomic_write_json(path: Path, data) -> None:
    """
    Atomically write JSON.

    Data is initially written to a temporary file and then renamed.
    """

    temporary_path = path.with_suffix(path.suffix + ".tmp")

    with temporary_path.open("w", encoding="utf-8") as file_handle:
        json.dump(
            data,
            file_handle,
            indent=4,
            ensure_ascii=False,
        )

        file_handle.flush()
        os.fsync(file_handle.fileno())

    os.replace(temporary_path, path)


def atomic_write_text(path: Path, content: str) -> None:
    """Atomically write text content."""

    temporary_path = path.with_suffix(path.suffix + ".tmp")

    with temporary_path.open("w", encoding="utf-8") as file_handle:
        file_handle.write(content)
        file_handle.flush()
        os.fsync(file_handle.fileno())

    os.replace(temporary_path, path)


# ============================================================
# LOG CLASSIFICATION
# ============================================================

def classify_severity(message: str) -> str:
    """Determine the highest severity found in a log message."""

    if CRITICAL_PATTERN.search(message):
        return "CRITICAL"

    if ERROR_PATTERN.search(message):
        return "ERROR"

    if WARNING_PATTERN.search(message):
        return "WARNING"

    return "UNKNOWN"


def is_incident_message(message: str) -> bool:
    """Return True when a log message represents a warning or an error."""

    return bool(SEVERITY_PATTERN.search(message))


def is_continuation_line(line: str) -> bool:
    """
    Identify probable continuation lines.

    Examples include:
    - Python traceback stack frames
    - Java stack traces
    - Indented multiline exception messages
    - Lines beginning with 'Caused by'
    """

    stripped = line.strip()

    if not stripped:
        return False

    continuation_patterns = (
        line.startswith((" ", "\t")),
        stripped.startswith("at "),
        stripped.startswith("File "),
        stripped.startswith("Caused by:"),
        stripped.startswith("Suppressed:"),
        stripped.startswith("During handling of"),
        stripped.startswith("The above exception"),
        stripped.startswith("Traceback "),
        stripped.startswith("... "),
    )

    return any(continuation_patterns)


# ============================================================
# INCIDENT NORMALIZATION
# ============================================================

def normalize_message(message: str) -> str:
    """
    Normalize dynamic values so repeated occurrences generate the same
    incident fingerprint.

    The normalization keeps the meaningful error structure while replacing
    common variable values such as timestamps, UUIDs, IP addresses, request
    IDs, process IDs, ports, memory addresses and numbers.
    """

    normalized = message.strip().lower()

    for pattern in TIMESTAMP_PATTERNS:
        normalized = pattern.sub("<timestamp>", normalized)

    normalized = UUID_PATTERN.sub("<uuid>", normalized)
    normalized = IPV4_PATTERN.sub("<ipv4>", normalized)
    normalized = IPV6_PATTERN.sub("<ipv6>", normalized)
    normalized = EMAIL_PATTERN.sub("<email>", normalized)
    normalized = URL_PATTERN.sub("<url>", normalized)

    normalized = FILE_LINE_PATTERN.sub(
        lambda match: f"{match.group('file')}:<line>",
        normalized,
    )

    normalized = HEX_ADDRESS_PATTERN.sub("<hex_address>", normalized)
    normalized = REQUEST_ID_PATTERN.sub(
        lambda match: f"{match.group(1).lower()}=<id>",
        normalized,
    )
    normalized = PID_PATTERN.sub(
        lambda match: f"{match.group(1).lower()}=<pid>",
        normalized,
    )
    normalized = PORT_PATTERN.sub("port=<port>", normalized)
    normalized = LONG_HEX_PATTERN.sub("<hex_value>", normalized)
    normalized = QUOTED_NUMBER_PATTERN.sub("<number>", normalized)
    normalized = NUMBER_PATTERN.sub("<number>", normalized)

    normalized = normalized.replace("\\n", " ")
    normalized = WHITESPACE_PATTERN.sub(" ", normalized)
    normalized = normalized.strip(" \t\r\n-:;,")

    return normalized


def create_fingerprint(normalized_message: str) -> str:
    """Create a stable SHA-256 fingerprint."""

    return hashlib.sha256(
        normalized_message.encode("utf-8")
    ).hexdigest()


# ============================================================
# INCIDENT FILE MANAGEMENT
# ============================================================

def incident_file_path(incident_id: str) -> Path:
    """Return the active incident text-file path."""

    return INCIDENT_DIRECTORY / f"{incident_id}.txt"


def generate_incident_id(fingerprint: str) -> str:
    """Create a readable incident ID."""

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"INC-{timestamp}-{fingerprint[:8].upper()}"


def incident_to_text(incident: dict) -> str:
    """Convert incident metadata into a readable text file."""

    recent_examples = incident.get("recent_examples", [])

    examples_text = "\n".join(
        f"{index}. {example}"
        for index, example in enumerate(recent_examples, start=1)
    )

    if not examples_text:
        examples_text = "No examples available"

    return f"""INCIDENT DETAILS
================

Incident ID       : {incident["incident_id"]}
Status            : {incident["status"]}
Severity          : {incident["severity"]}
Occurrence Count  : {incident["occurrence_count"]}
First Seen UTC    : {incident["first_seen"]}
Last Seen UTC     : {incident["last_seen"]}
Source Log        : {incident["source_log"]}
Fingerprint       : {incident["fingerprint"]}

NORMALIZED MESSAGE
==================

{incident["normalized_message"]}

FIRST ORIGINAL MESSAGE
======================

{incident["first_original_message"]}

LATEST ORIGINAL MESSAGE
=======================

{incident["latest_original_message"]}

RECENT OCCURRENCES
==================

{examples_text}
"""


def write_incident_file(incident: dict) -> Path:
    """Create or update the incident text file."""

    path = incident_file_path(incident["incident_id"])
    atomic_write_text(path, incident_to_text(incident))
    return path


def register_incident(
    message: str,
    source_log: Path,
) -> tuple[dict, bool]:
    """
    Create a new incident or update an existing incident.

    Returns:
        incident: Incident dictionary.
        created: True if the incident is new.
    """

    normalized_message = normalize_message(message)
    fingerprint = create_fingerprint(normalized_message)

    incident_index = load_json(
        INCIDENT_INDEX_FILE,
        {},
    )

    now = utc_now()

    if fingerprint in incident_index:
        incident = incident_index[fingerprint]

        if incident.get("status") == "OPEN":
            incident["occurrence_count"] += 1
            incident["last_seen"] = now
            incident["latest_original_message"] = message
            incident["severity"] = classify_severity(message)

            recent_examples = incident.setdefault(
                "recent_examples",
                [],
            )

            recent_examples.append(message)

            incident["recent_examples"] = recent_examples[
                -MAX_RECENT_CONTEXT_LINES:
            ]

            incident_index[fingerprint] = incident

            atomic_write_json(
                INCIDENT_INDEX_FILE,
                incident_index,
            )

            write_incident_file(incident)

            return incident, False

    incident_id = generate_incident_id(fingerprint)

    incident = {
        "incident_id": incident_id,
        "status": "OPEN",
        "severity": classify_severity(message),
        "occurrence_count": 1,
        "first_seen": now,
        "last_seen": now,
        "source_log": str(source_log),
        "fingerprint": fingerprint,
        "normalized_message": normalized_message,
        "first_original_message": message,
        "latest_original_message": message,
        "recent_examples": [message],
    }

    incident_index[fingerprint] = incident

    atomic_write_json(
        INCIDENT_INDEX_FILE,
        incident_index,
    )

    write_incident_file(incident)

    return incident, True


# ============================================================
# INCIDENT RESOLUTION AND ARCHIVAL
# ============================================================

def resolve_incident(
    incident_id: str,
    resolution_summary: str,
    llm_report: Optional[str] = None,
) -> Path:
    """
    Resolve an incident after LLM analysis.

    Processing:
    1. Locate the active incident.
    2. Add the resolution details.
    3. Copy the incident to dump/resolved.
    4. Verify the copied file.
    5. Remove the active incident text file.
    6. Mark the incident as resolved in the incident index.

    This function can later be called by the LLM orchestration layer.
    """

    incident_index = load_json(
        INCIDENT_INDEX_FILE,
        {},
    )

    matched_fingerprint = None
    matched_incident = None

    for fingerprint, incident in incident_index.items():
        if incident.get("incident_id") == incident_id:
            matched_fingerprint = fingerprint
            matched_incident = incident
            break

    if matched_incident is None or matched_fingerprint is None:
        raise ValueError(
            f"Incident not found: {incident_id}"
        )

    if matched_incident.get("status") == "RESOLVED":
        archived_file = matched_incident.get("archived_file")

        if archived_file:
            return Path(archived_file)

        raise ValueError(
            f"Incident {incident_id} is already resolved"
        )

    active_file = incident_file_path(incident_id)

    if not active_file.exists():
        raise FileNotFoundError(
            f"Active incident file does not exist: {active_file}"
        )

    resolved_at = utc_now()

    resolved_content = active_file.read_text(
        encoding="utf-8"
    )

    resolved_content += f"""

RESOLUTION DETAILS
==================

Resolved At UTC   : {resolved_at}
Resolved By       : LLM resolution workflow

Resolution Summary:
{resolution_summary.strip()}
"""

    if llm_report:
        resolved_content += f"""

LLM RCA REPORT
==============

{llm_report.strip()}
"""

    archive_timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    archive_file = (
        RESOLVED_DIRECTORY
        / f"{incident_id}_resolved_{archive_timestamp}.txt"
    )

    atomic_write_text(
        archive_file,
        resolved_content,
    )

    if not archive_file.exists():
        raise OSError(
            f"Failed to create archive file: {archive_file}"
        )

    if archive_file.stat().st_size == 0:
        archive_file.unlink(missing_ok=True)

        raise OSError(
            "Archived incident file is empty. "
            "The active incident was not removed."
        )

    matched_incident["status"] = "RESOLVED"
    matched_incident["resolved_at"] = resolved_at
    matched_incident["resolution_summary"] = resolution_summary
    matched_incident["archived_file"] = str(archive_file)

    incident_index[matched_fingerprint] = matched_incident

    atomic_write_json(
        INCIDENT_INDEX_FILE,
        incident_index,
    )

    active_file.unlink()

    print(
        f"[RESOLVED] {incident_id} archived to {archive_file}"
    )

    return archive_file


# ============================================================
# LOG FILE MONITOR
# ============================================================

class LogFileMonitor:
    """
    Monitor one local log file.

    Features:
    - Continues from the last saved offset after restart.
    - Detects truncation.
    - Detects log rotation.
    - Flushes pending multiline incidents.
    - Uses persistent state.
    """

    def __init__(
        self,
        log_path: Path,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        start_from_beginning: bool = False,
    ):
        self.log_path = log_path.resolve()
        self.poll_interval = poll_interval
        self.start_from_beginning = start_from_beginning

        self.pending_incident_lines: list[str] = []
        self.current_inode: Optional[int] = None
        self.current_offset = 0

    def load_monitor_state(self) -> None:
        """Load the saved file offset and inode."""

        state = load_json(
            MONITOR_STATE_FILE,
            {},
        )

        saved_path = state.get("log_path")

        if saved_path != str(self.log_path):
            self.current_inode = None
            self.current_offset = 0
            return

        self.current_inode = state.get("inode")
        self.current_offset = int(
            state.get("offset", 0)
        )

    def save_monitor_state(self) -> None:
        """Persist offset and inode."""

        state = {
            "log_path": str(self.log_path),
            "inode": self.current_inode,
            "offset": self.current_offset,
            "updated_at": utc_now(),
        }

        atomic_write_json(
            MONITOR_STATE_FILE,
            state,
        )

    def flush_pending_incident(self) -> None:
        """Create or update an incident from the pending lines."""

        if not self.pending_incident_lines:
            return

        message = "\n".join(
            self.pending_incident_lines
        ).strip()

        self.pending_incident_lines = []

        if not message:
            return

        message = message[:MAX_MESSAGE_LENGTH]

        incident, created = register_incident(
            message=message,
            source_log=self.log_path,
        )

        if created:
            print(
                f"[NEW INCIDENT] "
                f"{incident['incident_id']} | "
                f"{incident['severity']} | "
                f"{incident['normalized_message'][:200]}"
            )
        else:
            print(
                f"[DUPLICATE UPDATED] "
                f"{incident['incident_id']} | "
                f"Count: {incident['occurrence_count']}"
            )

    def process_line(self, line: str) -> None:
        """Process one line from the monitored log."""

        line = line.rstrip("\r\n")

        if not line:
            self.flush_pending_incident()
            return

        if is_incident_message(line):
            self.flush_pending_incident()

            self.pending_incident_lines = [line]
            return

        if (
            self.pending_incident_lines
            and is_continuation_line(line)
        ):
            self.pending_incident_lines.append(line)
            return

        self.flush_pending_incident()

    def determine_start_offset(
        self,
        inode: int,
        file_size: int,
    ) -> int:
        """Determine where monitoring should start."""

        if self.start_from_beginning:
            return 0

        if (
            self.current_inode == inode
            and self.current_offset <= file_size
        ):
            return self.current_offset

        if self.current_inode is None:
            return file_size

        return 0

    def monitor_open_file(self) -> None:
        """Monitor the currently active log file."""

        with self.log_path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file_handle:

            stat_result = os.fstat(
                file_handle.fileno()
            )

            inode = stat_result.st_ino
            file_size = stat_result.st_size

            start_offset = self.determine_start_offset(
                inode,
                file_size,
            )

            file_handle.seek(
                start_offset,
                os.SEEK_SET,
            )

            self.current_inode = inode
            self.current_offset = start_offset
            self.save_monitor_state()

            print(
                f"[MONITORING] {self.log_path}"
            )
            print(
                f"[POSITION] inode={inode}, "
                f"offset={start_offset}"
            )

            while RUNNING:
                line = file_handle.readline()

                if line:
                    self.current_offset = (
                        file_handle.tell()
                    )

                    self.process_line(line)
                    self.save_monitor_state()
                    continue

                self.flush_pending_incident()

                try:
                    active_stat = self.log_path.stat()
                except FileNotFoundError:
                    print(
                        "[INFO] Log file temporarily unavailable. "
                        "Waiting for recreation."
                    )
                    return

                if active_stat.st_ino != inode:
                    print(
                        "[INFO] Log rotation detected."
                    )
                    return

                if active_stat.st_size < self.current_offset:
                    print(
                        "[INFO] Log truncation detected."
                    )

                    file_handle.seek(
                        0,
                        os.SEEK_SET,
                    )

                    self.current_offset = 0
                    self.save_monitor_state()

                time.sleep(self.poll_interval)

    def run(self) -> None:
        """Continuously monitor the configured log file."""

        self.load_monitor_state()

        while RUNNING:
            if not self.log_path.exists():
                print(
                    f"[WAITING] Log file does not exist: "
                    f"{self.log_path}"
                )

                time.sleep(self.poll_interval)
                continue

            if not self.log_path.is_file():
                raise ValueError(
                    f"Path is not a regular file: "
                    f"{self.log_path}"
                )

            try:
                self.monitor_open_file()
            except PermissionError as error:
                print(
                    f"[ERROR] Permission denied: {error}",
                    file=sys.stderr,
                )
                time.sleep(self.poll_interval)
            except OSError as error:
                print(
                    f"[ERROR] Log monitoring error: {error}",
                    file=sys.stderr,
                )
                time.sleep(self.poll_interval)

        self.flush_pending_incident()
        self.save_monitor_state()


# ============================================================
# SIGNAL HANDLING
# ============================================================

def handle_shutdown_signal(
    signal_number,
    frame,
) -> None:
    """Stop monitoring gracefully."""

    del signal_number
    del frame

    global RUNNING
    RUNNING = False

    print(
        "\n[INFO] Shutdown requested. "
        "Finishing pending processing."
    )


# ============================================================
# USER INPUT
# ============================================================

def ask_for_log_path() -> Path:
    """Ask the user to provide a log file path."""

    while True:
        supplied_path = input(
            "Enter the complete log file path to monitor:\n> "
        ).strip()

        expanded_path = os.path.expandvars(
            os.path.expanduser(supplied_path)
        )

        log_path = Path(expanded_path).resolve()

        if not log_path.exists():
            print(
                f"Log file does not exist: {log_path}"
            )

            retry = input(
                "Wait for this file to be created? [y/N]: "
            ).strip().lower()

            if retry in {"y", "yes"}:
                return log_path

            continue

        if not log_path.is_file():
            print(
                "The supplied path is not a regular file."
            )
            continue

        if not os.access(log_path, os.R_OK):
            print(
                f"The log file is not readable: {log_path}"
            )
            continue

        return log_path


# ============================================================
# COMMAND-LINE OPERATIONS
# ============================================================

def monitor_command(args) -> None:
    """Start log monitoring."""

    if args.log_file:
        log_path = Path(
            os.path.expandvars(
                os.path.expanduser(args.log_file)
            )
        ).resolve()
    else:
        log_path = ask_for_log_path()

    monitor = LogFileMonitor(
        log_path=log_path,
        poll_interval=args.poll_interval,
        start_from_beginning=args.from_beginning,
    )

    monitor.run()


def resolve_command(args) -> None:
    """Resolve and archive an incident."""

    if args.resolution_file:
        resolution_summary = Path(
            args.resolution_file
        ).read_text(
            encoding="utf-8"
        )
    else:
        resolution_summary = args.summary

    llm_report = None

    if args.llm_report:
        llm_report = Path(
            args.llm_report
        ).read_text(
            encoding="utf-8"
        )

    archive_file = resolve_incident(
        incident_id=args.incident_id,
        resolution_summary=resolution_summary,
        llm_report=llm_report,
    )

    print(
        f"Archived file: {archive_file}"
    )


def list_command() -> None:
    """List all currently open incidents."""

    incident_index = load_json(
        INCIDENT_INDEX_FILE,
        {},
    )

    open_incidents = [
        incident
        for incident in incident_index.values()
        if incident.get("status") == "OPEN"
    ]

    if not open_incidents:
        print("No open incidents.")
        return

    open_incidents.sort(
        key=lambda item: item.get("last_seen", ""),
        reverse=True,
    )

    print("\nOPEN INCIDENTS")
    print("=" * 100)

    for incident in open_incidents:
        print(
            f"ID       : {incident['incident_id']}"
        )
        print(
            f"Severity : {incident['severity']}"
        )
        print(
            f"Count    : {incident['occurrence_count']}"
        )
        print(
            f"Last Seen: {incident['last_seen']}"
        )
        print(
            f"Message  : "
            f"{incident['normalized_message'][:300]}"
        )
        print("-" * 100)


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Monitor a local server log and create "
            "deduplicated text-file incidents."
        )
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    monitor_parser = subparsers.add_parser(
        "monitor",
        help="Monitor a log file",
    )

    monitor_parser.add_argument(
        "--log-file",
        help=(
            "Complete log-file path. If omitted, "
            "the application asks for it."
        ),
    )

    monitor_parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help="Polling interval in seconds",
    )

    monitor_parser.add_argument(
        "--from-beginning",
        action="store_true",
        help=(
            "Read the existing log content from the beginning. "
            "Without this option, a new monitor starts at EOF."
        ),
    )

    resolve_parser = subparsers.add_parser(
        "resolve",
        help="Archive and remove an active incident",
    )

    resolve_parser.add_argument(
        "incident_id",
        help="Incident ID to resolve",
    )

    resolution_group = (
        resolve_parser.add_mutually_exclusive_group(
            required=True
        )
    )

    resolution_group.add_argument(
        "--summary",
        help="Resolution summary",
    )

    resolution_group.add_argument(
        "--resolution-file",
        help=(
            "Text file containing the resolution summary"
        ),
    )

    resolve_parser.add_argument(
        "--llm-report",
        help=(
            "Optional text file containing the complete "
            "LLM RCA report"
        ),
    )

    subparsers.add_parser(
        "list",
        help="List currently open incidents",
    )

    return parser


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """Application entry point."""

    create_directories()

    signal.signal(
        signal.SIGINT,
        handle_shutdown_signal,
    )

    signal.signal(
        signal.SIGTERM,
        handle_shutdown_signal,
    )

    parser = build_argument_parser()
    args = parser.parse_args()

    if not args.command:
        args.command = "monitor"
        args.log_file = None
        args.poll_interval = DEFAULT_POLL_INTERVAL
        args.from_beginning = False

    if args.command == "monitor":
        monitor_command(args)
    elif args.command == "resolve":
        resolve_command(args)
    elif args.command == "list":
        list_command()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
