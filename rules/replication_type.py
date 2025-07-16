def get_metadata():
    return {
        "id": "replication_type",
        "severity": "Medium",
        "category": "Storage",
        "description": "Detects use of 'GRS' replication which may be less resilient than ZRS or LRS."
    }

def scan(file_name, code, config):
    results = []
    if not config.get("replication_type", True):
        return []

    lines = code.split("\n")
    for i, line in enumerate(lines):
        if "# skip-rule: replication_type" in line.lower():
            continue

        if "account_replication_type" in line.lower() and "\"GRS\"" in line:
            results.append({
                "rule": "replication_type",
                "severity": "Medium",
                "category": "Storage",
                "file": file_name,
                "line": i + 1,
                "message": "⚠️ 'GRS' replication type detected — may have limited durability",
                "suggestion": "Consider using 'ZRS' or 'LRS' for better availability and region-level redundancy."
            })

    return results