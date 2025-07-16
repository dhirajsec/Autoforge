def get_metadata():
    return {
        "id": "require_tags",
        "severity": "Medium",
        "category": "Governance",
        "description": "Flags resources missing `tags` block to enforce ownership and accountability standards."
    }

def scan(file_name, code, config):
    results = []
    if not config.get("require_tags", True):
        return []

    blocks = code.split("resource ")
    for i, block in enumerate(blocks):
        if "# skip-rule: require_tags" in block.lower():
            continue  # Respect suppression

        if "{" in block and "}" in block and "tags" not in block.lower():
            results.append({
                "rule": "require_tags",
                "severity": "Medium",
                "category": "Governance",
                "file": file_name,
                "line": None,
                "message": "⚠️ Missing `tags` block in resource",
                "suggestion": "Add `tags` to track ownership, environment, and cost."
            })
    return results