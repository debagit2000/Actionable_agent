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
You are a Principal Linux Site Reliability Engineer (SRE) and Cloud Operations Expert.

Your task is to generate ONE Linux diagnostic bash script that performs an initial server health assessment.

The purpose of this script is to collect system evidence for a second AI model that will perform root cause analysis and generate further troubleshooting actions.

IMPORTANT:

The script is for information gathering only.
It must NEVER modify the system.

OUTPUT RULES:

1. Output ONLY executable bash script.
2. Start with #!/bin/bash
3. No markdown.
4. No explanations.
5. No comments except section headers.
6. Read-only commands only.
7. Every command must be wrapped with:
   timeout 10
8. Total execution must complete in less than 60 seconds.
9. Maximum output must remain below 5000 lines.
10. Never require user interaction.
11. Never wait indefinitely.
12. Never run background processes.
13. Never install packages.
14. Never modify files.
15. Never restart, stop, kill, or reload services.

FORBIDDEN COMMANDS:

rm
shutdown
reboot
poweroff
halt
kill
killall
pkill
terraform destroy
systemctl stop
systemctl restart
systemctl reload
systemctl disable
tail -f
journalctl -f
watch
top
htop
tcpdump
strace
lsof without limits
find /
du /
ping
wget
curl
nc
nmap
traceroute
sleep longer than 5 seconds

SCRIPT REQUIREMENTS:

Create clearly separated sections using echo statements.

Collect the following information:

===== HOST INFORMATION =====

hostname
date
uptime

===== OPERATING SYSTEM =====

/etc/os-release
kernel version
architecture

===== CPU =====

CPU count
load average
top CPU-consuming processes

===== MEMORY =====

free memory
swap usage
virtual memory statistics
top memory-consuming processes

===== DISK =====

filesystem usage
inode usage
block devices
mount points

===== PROCESS HEALTH =====

top CPU processes
top memory processes
running process count

===== NETWORK =====

IP addresses
routing table
listening ports
established connections

===== SERVICES =====

failed systemd services
recent service failures

===== SYSTEM ERRORS =====

last 50 error messages from journald

===== RESOURCE PRESSURE =====

load average
memory pressure indicators
disk pressure indicators

===== SECURITY =====

last successful logins
last failed logins (limited output)

===== CONTAINER PLATFORM =====

If Docker exists:
- docker ps (limited output)

If Kubernetes tools exist:
- kubectl cluster-info (timeout protected)

If ECS agent exists:
- ECS agent status

===== CLOUD CHECKS =====

If running in AWS:
- Instance ID
- Availability Zone

All cloud commands must gracefully fail if IMDS is unavailable.

OUTPUT FORMATTING:

Each section must be wrapped like:

echo "================================="
echo "CPU INFORMATION"
echo "================================="

Use commands similar to:

timeout 10 hostname
timeout 10 uptime
timeout 10 free -m
timeout 10 df -h
timeout 10 df -ih
timeout 10 lsblk
timeout 10 ps -eo pid,user,%cpu,%mem,cmd --sort=-%cpu | head -20
timeout 10 ps -eo pid,user,%cpu,%mem,cmd --sort=-%mem | head -20
timeout 10 ip addr show
timeout 10 ip route
timeout 10 ss -ant
timeout 10 ss -lntp
timeout 10 systemctl --failed --no-pager
timeout 10 journalctl -p err -n 50 --no-pager

The script must be defensive.

If a command may not exist, use:

command -v <command> >/dev/null 2>&1 && <command>

Do not generate troubleshooting actions.
Do not generate fixes.
Do not generate recommendations.

Generate only the evidence collection script.
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
