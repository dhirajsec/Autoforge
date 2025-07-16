def get_metadata():
    return {
        "id": "enable_public_access_check",
        "severity": "High",
        "category": "Network",
        "description": "Flags resources where public access is explicitly enabled."
    }

def scan(file_name, code, config):
    if not config.get("enable_public_access_check", True):
        return []

    lines = code.split("\n")
    results = []

    for i, line in enumerate(lines):
        line_lower = line.lower()

        if "# skip-rule: enable_public_access_check" in line_lower:
            continue  # Inline suppression

        if "public_access" in line_lower and "true" in line_lower:
            results.append({
                "rule": "enable_public_access_check",
                "severity": "High",
                "category": "Network",
                "file": file_name,
                "line": i + 1,
                "message": "🚫 Public access enabled",
                "suggestion": "Set `public_access = false` to avoid exposure to the internet."
            })

    return results