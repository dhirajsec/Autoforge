import re

def get_metadata():
    return {
        "id": "check_open_ssh_ingress",
        "severity": "Critical",
        "category": "Network",
        "description": "Detects open SSH access (port 22) exposed to the world via 0.0.0.0/0 or *."
    }

def scan(file_name, code, config):
    results = []
    if not config.get("check_open_ssh_ingress", True):
        return []

    lines = code.split("\n")
    for i, line in enumerate(lines):
        if re.search(r"from_port\s*=\s*22", line) or re.search(r"destination_port_range\s*=\s*\"22\"", line):
            context = lines[i:i+6]  # check a few lines below
            if any("0.0.0.0/0" in c or "\"*\"" in c for c in context):
                results.append({
                    "rule": "check_open_ssh_ingress",
                    "severity": "Critical",
                    "category": "Network",
                    "file": file_name,
                    "line": i + 1,
                    "message": "🚨 Open SSH port detected with global access",
                    "suggestion": "Restrict SSH access to specific IP ranges instead of 0.0.0.0/0."
                })
    return results