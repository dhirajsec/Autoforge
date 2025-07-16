from datetime import datetime

def summarize_scan(scan_results):
    total_files = len(scan_results)
    passed = failed = warnings = 0

    for results in scan_results.values():
        if len(results) == 1 and isinstance(results[0], dict) and results[0].get("rule") == "All Clear":
            passed += 1
            continue

        for result in results:
            if isinstance(result, dict):
                severity = result.get("severity", "none")
            else:
                severity = "none"  # fallback if result is a string

            if severity == "high":
                failed += 1
            elif severity == "medium":
                warnings += 1
            elif severity == "none":
                passed += 1

    score = int(((passed / total_files) if total_files > 0 else 1) * 100)
    return {
        "files": total_files,
        "passed": passed,
        "warnings": warnings,
        "failed": failed,
        "score": score
    }

def format_as_html(scan_data):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = summarize_scan(scan_data)

    html = "<html><head><title>AutoForge Report</title></head><body>"
    html += "<h1>AutoForge Infrastructure Scan Report</h1>"
    html += f"<p><b>Generated:</b> {timestamp}</p>"

    html += "<table border='1' cellspacing='0' cellpadding='6'><tr><th>Metric</th><th>Value</th></tr>"
    html += f"<tr><td>Total .tf Files</td><td>{summary['files']}</td></tr>"
    html += f"<tr><td>✅ Passed</td><td>{summary['passed']}</td></tr>"
    html += f"<tr><td>⚠️ Warnings</td><td>{summary['warnings']}</td></tr>"
    html += f"<tr><td>🚫 Failed</td><td>{summary['failed']}</td></tr>"
    html += f"<tr><td>🧠 Compliance Score</td><td>{summary['score']}%</td></tr>"
    html += "</table><hr>"

    for file, issues in scan_data.items():
        html += f"<h2>{file}</h2><ul>"
        passed = warnings = failed = 0

        for issue in issues:
            if isinstance(issue, dict):
                message = issue.get("message", str(issue))
                severity = issue.get("severity", "none")
                suggestion = issue.get("suggestion", "")
            else:
                message = str(issue)
                severity = "none"
                suggestion = ""

            color = {
                "none": "green",
                "medium": "orange",
                "high": "red"
            }.get(severity, "gray")

            html += f"<li style='color:{color}'>{message}"
            if suggestion:
                html += f"<br><span style='color:blue'>💡 Suggested Fix: {suggestion}</span>"
            html += "</li>"

            if severity == "high": failed += 1
            elif severity == "medium": warnings += 1
            elif severity == "none": passed += 1

        total = len(issues)
        file_score = int((passed / total) * 100) if total else 100
        html += "</ul>"
        html += f"<p><b>Compliance Score:</b> {file_score}%</p>"
        html += f"<p>✅ Passed: {passed} &nbsp; ⚠️ Warnings: {warnings} &nbsp; 🚫 Failed: {failed}</p><hr>"

    html += "</body></html>"
    return html

def format_as_markdown(scan_data):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = summarize_scan(scan_data)

    md = "# AutoForge Infrastructure Scan Report\n\n"
    md += f"**Generated:** {timestamp}\n\n"
    md += "| Metric | Value |\n|--------|-------|\n"
    md += f"| Total `.tf` files | {summary['files']} |\n"
    md += f"| ✅ Passed checks | {summary['passed']} |\n"
    md += f"| ⚠️ Warnings | {summary['warnings']} |\n"
    md += f"| 🚫 Critical failures | {summary['failed']} |\n"
    md += f"| 🧠 Compliance score | {summary['score']}% |\n\n"
    md += "---\n\n"

    for file, issues in scan_data.items():
        md += f"## {file}\n\n"
        passed = warnings = failed = 0

        for issue in issues:
            if isinstance(issue, dict):
                message = issue.get("message", str(issue))
                severity = issue.get("severity", "none")
                suggestion = issue.get("suggestion", "")
            else:
                message = str(issue)
                severity = "none"
                suggestion = ""

            md += f"- {message}\n"
            if suggestion:
                md += f"  💡 Suggested Fix: {suggestion}\n"

            if severity == "high": failed += 1
            elif severity == "medium": warnings += 1
            elif severity == "none": passed += 1

        total = len(issues)
        file_score = int((passed / total) * 100) if total else 100
        md += f"\n**Compliance Score:** {file_score}%\n"
        md += f"✅ Passed: {passed}  |  ⚠️ Warnings: {warnings}  |  🚫 Failed: {failed}\n\n"
        md += "---\n"

    return md
