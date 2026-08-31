#!/usr/bin/env python3

import os
import re
import json
import requests
import subprocess
from dotenv import load_dotenv
from datetime import datetime
from cryptography.fernet import Fernet


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

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1
    }

    response = requests.post(
        OPENROUTER_URL,
        headers=headers,
        json=payload,
        timeout=120
    )

    response.raise_for_status()

    data = response.json()

    return data['choices'][0]['message']

# =====================================================
# BASH SCRIPT GENERATION
# =====================================================

def generate_bash_script(issue):

    prompt = f"""
You are a Senior Linux and CloudOps Engineer.

Generate ONLY executable bash script.

Rules:
1. Output bash script only
2. Start with #!/bin/bash
3. No markdown
4. No explanations
5. Diagnostic commands only
6. Read-only commands only
7. Must contain echo statements
8. Never modify system configuration

Issue:

{issue}
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
