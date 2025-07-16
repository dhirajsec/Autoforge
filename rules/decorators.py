import re

def suppressible(rule_id):
    def decorator(scan_func):
        def wrapped(file_name, code, config):
            results = scan_func(file_name, code, config)
            suppressed_lines = get_suppressed_lines(code, rule_id)

            for result in results:
                line_no = result.get("line", None)
                if line_no and line_no in suppressed_lines:
                    result["suppressed"] = True
                else:
                    result["suppressed"] = False
            return [r for r in results if not r.get("suppressed", False)]
        return wrapped
    return decorator

def get_suppressed_lines(code, rule_id):
    suppressed = set()
    pattern = re.compile(rf"#\s*skip-rule:\s*{rule_id}", re.IGNORECASE)

    for i, line in enumerate(code.split("\n")):
        if pattern.search(line):
            suppressed.add(i + 1)  # lines are 1-indexed
    return suppressed