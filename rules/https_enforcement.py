def get_metadata():
    return {
        "id": "enable_https_check",
        "severity": "High",
        "category": "Security",
        "description": "Detects storage resources that allow non-HTTPS traffic."
    }

def scan(file_name, code, config):
    results = []
    if not config.get("enable_https_check", True):
        return []

    lines = code.split("\n")
    for i, line in enumerate(lines):
        if "enable_https_traffic_only" in line.lower() and "false" in line.lower():
            results.append({
                "rule": "enable_https_check",
                "severity": "High",
                "category": "Security",
                "file": file_name,
                "line": i + 1,
                "message": "🚫 HTTPS traffic not enforced",
                "suggestion": "Set `enable_https_traffic_only = true` to enforce secure communication."
            })
    return results