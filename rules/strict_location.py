def get_metadata():
    return {
        "id": "strict_location",
        "severity": "Medium",
        "category": "Configuration",
        "description": "Flags resources missing the `location` attribute when strict mode is enabled."
    }

def scan(file_name, code, config):
    results = []
    if not config.get("strict_mode", False):
        return []

    if "# skip-rule: strict_location" in code.lower():
        return []

    lines = code.split("\n")
    if not any("location" in line.lower() for line in lines):
        results.append({
            "rule": "strict_location",
            "severity": "Medium",
            "category": "Configuration",
            "file": file_name,
            "line": None,
            "message": "⚠️ No `location` attribute found (strict mode)",
            "suggestion": "Add `location = ...` to ensure the resource is region-bound and compliant with deployment standards."
        })

    return results