def get_metadata():
    return {
        "id": "sensitive_output_leak",
        "severity": "High",
        "category": "Data Exposure",
        "description": "Flags exposure of sensitive variables inside output blocks."
    }

def scan(file_name, code, config):
    results = []
    if not config.get("sensitive_output_leak", True):
        return []

    if "# skip-rule: sensitive_output_leak" in code.lower():
        return []

    # Basic pattern detection
    if "variable" in code and "sensitive = true" in code:
        if "output" in code and "value" in code:
            results.append({
                "rule": "sensitive_output_leak",
                "severity": "High",
                "category": "Data Exposure",
                "file": file_name,
                "line": None,
                "message": "🚫 Sensitive variable exposed in output block",
                "suggestion": "Do not include sensitive variables in `output {}`."
            })

    return results