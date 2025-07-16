import re

def get_metadata():
    return {
        "id": "secrets_detector",
        "severity": "High",
        "category": "Security",
        "description": "Detects hardcoded secrets like access keys, passwords, and tokens in Terraform code."
    }

def scan(file_name, code, config):
    results = []
    if not config.get("secrets_detector", True):
        return []

    if "# skip-rule: secrets_detector" in code.lower():
        return []

    patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"(?i)aws_secret_access_key\s*=\s*\"[^\"]+\"",
        "Password": r"(?i)password\s*=\s*\"[^\"]+\"",
        "Generic Token": r"(?i)token\s*=\s*\"[^\"]+\""
    }

    lines = code.split("\n")
    for i, line in enumerate(lines):
        for label, pattern in patterns.items():
            if re.search(pattern, line):
                results.append({
                    "rule": "secrets_detector",
                    "severity": "High",
                    "category": "Security",
                    "file": file_name,
                    "line": i + 1,
                    "message": f"🚫 Potential secret detected: {label}",
                    "suggestion": "Remove or reference securely via environment variables, Vault, or encrypted state."
                })

    return results