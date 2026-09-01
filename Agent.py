#!/usr/bin/env python3

import os
import re
import json
import requests
import subprocess
from dotenv import load_dotenv
from datetime import datetime
from cryptography.fernet import Fernet

load_dotenv()

OLLAMA_URL = os.getenv(
"OLLAMA_URL",
"http://localhost:11434/api/generate")

MODEL_NAME = os.getenv(
"MODEL_NAME",
"qwen2.5:3b")


# =====================================================
# CONFIGURATION
# =====================================================


EXECUTION_TIMEOUT = 300

LOG_DIR = "logs"
SCRIPT_DIR = "scripts"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(SCRIPT_DIR, exist_ok=True)

# =====================================================
# ENCRYPTION
# =====================================================

KEY_FILE = "agent.key"

if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()

    with open(KEY_FILE, "wb") as f:
        f.write(key)

with open(KEY_FILE, "rb") as f:
    key = f.read()

cipher = Fernet(key)

# =====================================================
# OPENROUTER CLIENT
# =====================================================

def call_llm(prompt):

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False
    }

    try:

        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=300
        )

        print("HTTP Status:", response.status_code)
        print("Response:", response.text[:500])

        response.raise_for_status()

        data = response.json()

        return data["response"]

    except Exception as e:
        print("Ollama Error:", str(e))
        raise
# =====================================================
# BASH SCRIPT GENERATION
# =====================================================


def generate_bash_script(issue):

    prompt = f"""
You are a Linux diagnostic script generator.

Create an executable, read-only Bash script to investigate this issue:

<issue>
{issue}
</issue>

Return only Bash code. Do not use Markdown fences. Do not explain the script.

Mandatory requirements:

1. Start exactly with:
#!/usr/bin/env bash

2. Add:
set -uo pipefail

3. Generate at least 8 real diagnostic commands.
Comments and echo statements do not count as diagnostic commands.

4. Every command that could block must use timeout 5.

5. Print a heading before every diagnostic section.

6. Collect live data from the current server.

7. Continue if a command fails.

8. Keep output bounded with head, tail, or command-specific limits.

9. Do not use:
rm, mv, cp, dd, mkfs, kill, pkill, reboot, shutdown, poweroff,
systemctl stop, systemctl restart, systemctl disable,
chmod, chown, sudo, su, curl, wget, ssh, scp, eval,
package managers, file redirection, or AWS write operations.

For a CPU issue, include actual commands for:

- Current date and hostname
- Uptime and load average
- CPU count and CPU information
- Per-process CPU usage
- Memory usage
- vmstat
- Process state summary
- Load-producing processes
- Failed systemd units
- Recent kernel messages related to CPU, lockups, stalls, OOM, or throttling
- Container CPU usage if Docker exists
- A final findings summary based on collected values

Use commands such as:
date, hostname, uptime, nproc, lscpu, ps, top, free, vmstat,
systemctl, journalctl, dmesg, grep, awk, head, sort, docker.

The script must execute commands, not merely describe them.

Generate the Bash script now.
"""

    return call_llm(prompt)

# =====================================================
# SECURITY VALIDATION
# =====================================================

FORBIDDEN_COMMANDS = [

    "rm ",
    "rm -rf",
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "mkfs",
    "fdisk",
    "dd if=",
    "userdel",
    "groupdel",
    ":(){:|:&};:",
    "curl | bash",
    "wget | bash",
    "chmod 777",
    "kill -9",
    "systemctl stop",
    "systemctl disable",
    "terraform destroy"
]


def validate_script(script):

    script_lower = script.lower()

    for cmd in FORBIDDEN_COMMANDS:

        if cmd.lower() in script_lower:
            raise Exception(
                f"Blocked dangerous command: {cmd}"
            )

    print("[+] Script validation successful")

# =====================================================
# SAVE SCRIPT
# =====================================================

def save_script(script):

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    script_path = (
        f"{SCRIPT_DIR}/script_{timestamp}.sh"
    )

    with open(
        script_path,
        "w"
    ) as f:
        f.write(script)

    os.chmod(script_path, 0o750)

    return script_path

# =====================================================
# EXECUTE SCRIPT
# =====================================================

def execute_script(script_path):

    try:

        result = subprocess.run(
            ["bash", script_path],
            capture_output=True,
            text=True,
            timeout=EXECUTION_TIMEOUT
        )

        return {
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    except subprocess.TimeoutExpired:

        return {
            "return_code": -1,
            "stdout": "",
            "stderr": f"Script timed out after {EXECUTION_TIMEOUT} seconds"
        }
# =====================================================
# LOG SANITIZATION
# =====================================================

def sanitize_logs(text):

    text = re.sub(
        r'AKIA[0-9A-Z]{16}',
        '[AWS_ACCESS_KEY]',
        text
    )

    text = re.sub(
        r'(?i)password=.*',
        'password=[REDACTED]',
        text
    )

    text = re.sub(
        r'(?i)secret=.*',
        'secret=[REDACTED]',
        text
    )

    text = re.sub(
        r'(?i)token=.*',
        'token=[REDACTED]',
        text
    )

    text = re.sub(
        r'(?i)apikey=.*',
        'apikey=[REDACTED]',
        text
    )

    return text

# =====================================================
# SAVE ENCRYPTED LOG
# =====================================================

def save_encrypted_log(data):

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        f"{LOG_DIR}/{timestamp}.enc"
    )

    encrypted = cipher.encrypt(
        json.dumps(
            data,
            indent=4
        ).encode()
    )

    with open(
        filename,
        "wb"
    ) as f:
        f.write(encrypted)

    return filename

# =====================================================
# RCA ANALYSIS
# =====================================================

def analyze_logs(issue, logs):

    prompt = f"""
Act as a Senior CloudOps Engineer.

Issue:
{issue}

Execution Logs:
{logs}

Provide:

1. Executive Summary
2. Root Cause
3. Severity
4. Resolution
5. Preventive Actions
6. Recommended Monitoring
"""

    return call_llm(prompt)

# =====================================================
# MAIN FLOW
# =====================================================

def process_issue(issue):

    print("\n[1] Generating Bash Script...\n")

    script = generate_bash_script(issue)

    print(script)

    print("\n[2] Validating Script...\n")

    validate_script(script)

    print("\n[3] Saving Script...\n")

    script_path = save_script(script)

    print(f"Saved: {script_path}")

    print("\n[4] Executing Script...\n")

    execution_result = execute_script(
        script_path
    )

    logs = json.dumps(
        execution_result,
        indent=4
    )

    sanitized_logs = sanitize_logs(logs)

    print("\n[5] Analyzing Logs...\n")

    analysis = analyze_logs(
        issue,
        sanitized_logs
    )

    print("\n[6] Saving Encrypted Audit Log...\n")

    log_file = save_encrypted_log(
        {
            "timestamp":
            datetime.now().isoformat(),

            "issue":
            issue,

            "script":
            script,

            "execution":
            execution_result,

            "analysis":
            analysis
        }
    )

    print(
        f"Encrypted Log File: {log_file}"
    )

    return analysis

# =====================================================
# ENTRYPOINT
# =====================================================

if __name__ == "__main__":

    print("\n========== CloudOps AI Agent ==========\n")

    issue = input(
        "Describe the issue:\n\n"
    )

    try:

        result = process_issue(issue)

        print("\n==============================")
        print(" RCA REPORT ")
        print("==============================\n")

        print(result)

    except Exception as e:

        print(
            f"\nERROR: {str(e)}"
        )
