import json

def get_metadata():
    return {
        "id": "iam_graph_mapper",
        "category": "Security",
        "severity": "Medium",
        "description": "Maps principal → permission → resource paths from IAM policy documents."
    }

def scan(filename, code, active_rules):
    results = []
    if "aws_iam_policy" not in code and "aws_iam_role" not in code:
        return results  # Skip irrelevant files

    lines = code.split("\n")
    for idx, line in enumerate(lines):
        if "policy =" in line or "assume_role_policy =" in line:
            # Try parsing JSON in next few lines
            joined = ""
            for j in range(idx, min(len(lines), idx + 10)):
                joined += lines[j]

            # Extract JSON blob (best-effort parsing)
            try:
                start = joined.index("{")
                end = joined.rindex("}") + 1
                policy_blob = joined[start:end]
                policy_json = json.loads(policy_blob)

                statements = policy_json.get("Statement", [])
                if isinstance(statements, dict):  # single statement
                    statements = [statements]

                for s in statements:
                    principal = s.get("Principal", "*")
                    action = s.get("Action", "*")
                    resource = s.get("Resource", "*")

                    message = f"🧠 IAM Access Path → Principal: `{principal}` → Action: `{action}` → Resource: `{resource}`"
                    result = {
                        "rule": "iam_graph_mapper",
                        "severity": "Medium",
                        "category": "Security",
                        "file": filename,
                        "line": idx + 1,
                        "message": message,
                        "suggestion": "Review and restrict overly broad actions and principals."
                    }

                    # Flag suspicious wildcards
                    if principal == "*" or action == "*" or resource == "*":
                        result["severity"] = "High"
                        result["message"] += " 🚨 Wildcard detected"

                    results.append(result)

            except Exception as e:
                continue  # Skip broken JSON

    return results