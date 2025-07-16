def get_metadata():
    return {
        "id": "wildcard_iam_policy",
        "severity": "Critical",
        "category": "IAM",
        "description": "Detects use of wildcard (`*`) in IAM policy actions or resources, which violates least privilege."
    }

def scan(file_name, code, config):
    results = []
    if not config.get("wildcard_iam_policy", True):
        return []

    if "# skip-rule: wildcard_iam_policy" in code.lower():
        return []

    lines = code.split("\n")
    for i, line in enumerate(lines):
        if '"Action": "*"' in line or '"Resource": "*"' in line:
            results.append({
                "rule": "wildcard_iam_policy",
                "severity": "Critical",
                "category": "IAM",
                "file": file_name,
                "line": i + 1,
                "message": "🚨 Wildcard used in IAM policy action or resource",
                "suggestion": "Avoid using `*` in IAM policies. Define specific actions and resources to enforce least privilege."
            })
    return results