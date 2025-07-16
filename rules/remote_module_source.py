def get_metadata():
    return {
        "id": "remote_module_source",
        "severity": "Medium",
        "category": "Module",
        "description": "Detects Terraform modules sourced from public GitHub URLs."
    }

def scan(file_name, code, config):
    results = []
    if not config.get("remote_module_source", True):
        return []

    lines = code.split("\n")
    for i, line in enumerate(lines):
        if "# skip-rule: remote_module_source" in line.lower():
            continue  # Respect inline suppression

        if "source" in line and "github.com" in line.lower():
            results.append({
                "rule": "remote_module_source",
                "severity": "Medium",
                "category": "Module",
                "file": file_name,
                "line": i + 1,
                "message": "🌐 Module sourced from public GitHub repo",
                "suggestion": "Use verified or internal module registries for stability and security."
            })

    return results