import json
import os
from typing import Dict, List

# ✅ Define supported compliance frameworks
FRAMEWORKS = {
    "cis": {
        "label": "CIS Benchmark",
        "controls": ["2.1.1", "4.1", "5.3"]
    },
    "nist": {
        "label": "NIST SP 800-53",
        "controls": ["AC-3", "AU-6", "SC-7"]
    }
}

def tag_rule(rule: Dict, frameworks: List[str]) -> Dict:
    """Attach compliance tags to a rule dictionary."""
    rule["tags"] = list(set(rule.get("tags", []) + frameworks))
    return rule

def scan_profiles_for_tags(config_folder: str = "configs") -> Dict[str, List[str]]:
    """Scan all profiles and build a coverage map per framework."""
    coverage = {fw: [] for fw in FRAMEWORKS}

    for filename in os.listdir(config_folder):
        if filename.endswith(".json"):
            path = os.path.join(config_folder, filename)
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
                rules = data.get("rules", {})
                for rule_name, rule_def in rules.items():
                    tags = rule_def.get("tags", [])
                    for fw in FRAMEWORKS:
                        if fw in tags:
                            coverage[fw].append(rule_name)

    return coverage

def export_coverage_report(coverage: Dict[str, List[str]], output_file: str = "reports/compliance_report.json") -> None:
    """Save a structured compliance report to a JSON file."""
    export_data = {
        "frameworks": {},
        "total_tagged_rules": sum(len(rules) for rules in coverage.values())
    }

    for fw, rules in coverage.items():
        export_data["frameworks"][fw] = {
            "label": FRAMEWORKS[fw]["label"],
            "rule_count": len(rules),
            "rules": sorted(rules)
        }

    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)
    print(f"✅ Compliance report saved to {output_file}")

if __name__ == "__main__":
    coverage = scan_profiles_for_tags()
    print("\n📊 Compliance Coverage Report")
    for fw, rules in coverage.items():
        print(f"- {FRAMEWORKS[fw]['label']} → {len(rules)} rules tagged")
        for rule in sorted(rules):
            print(f"  • {rule}")
    export_coverage_report(coverage)