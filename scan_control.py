import json
import os
import sys


sys.path.append(os.path.join(os.path.dirname(__file__), "utility"))

from utility.yaml_policy_loader import load_yaml_policies
from utility.graph_renderer import render_annotated_graph
from utility.profile_loader import load_profile
from utility.graph_query_engine import (
    find_paths_by_severity,
    count_edges_by_severity,
    get_edge_messages
)

PROFILE_PATH = "config.json"
FOLDER_PATH = "target_folder.txt"

def save_profile(profile, path=PROFILE_PATH):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=4)
        print("✅ Profile saved:", profile)
    except Exception as e:
        print("❌ Could not save profile:", e)

def load_profile(path=PROFILE_PATH):
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print("⚠️ Failed to load profile:", e)
    return {}

def save_target_folder(folder, path=FOLDER_PATH):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(folder.strip())
        print("📁 Target folder set:", folder)
    except Exception as e:
        print("❌ Failed to save scan folder:", e)

def get_target_folder(path=FOLDER_PATH):
    try:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
    except Exception as e:
        print("⚠️ Could not load target folder:", e)
    return "sample_tf"

def trigger_scan(folder, profile_path="configs/profiles/dev_profile.json", policy_path="configs/policies/access_rules.yaml"):
    print("🚀 Starting scan with profiles and policies...")
    print("📂 Folder:", folder)
    print("📜 Profile:", profile_path)
    print("🧩 Policies:", policy_path)

    profile = load_profile(profile_path)
    policies = load_yaml_policies(policy_path)

    raw_path = [
        {"source": "Lambda", "target": "admin-role", "action": "sts:AssumeRole", "tags": {"env": "dev"}},
        {"source": "IAM_Role", "target": "S3_Bucket", "action": "s3:ListBucket", "tags": {"encrypted": "false"}},
        {"source": "UnapprovedThirdParty", "target": "S3_Bucket", "action": "s3:ListBucket", "tags": {"env": "dev"}}
    ]

    result_path = []

    for edge in raw_path:
        source = edge.get("source")
        target = edge.get("target")
        action = edge.get("action")
        tags = edge.get("tags", {})

        if source in profile.get("exclude_roles", []) or target in profile.get("exclude_roles", []):
            print(f"⛔️ Skipping excluded edge: {source} ➞ {target}")
            continue

        edge["severity"] = profile.get("severity_overrides", {}).get(action, "low")

        for rule in policies:
            rule_type = next(iter(rule), None)
            rule_def = rule.get(rule_type)

            if not rule_type or not rule_def:
                print(f"⚠️ Skipping malformed rule: {rule}")
                continue

            from_match = rule_def.get("from") == source or rule_def.get("from") == "any"
            to_match = rule_def.get("to") == target or rule_def.get("to") == "any"

            if from_match and to_match:
                condition = rule_def.get("condition", {})
                reason = rule_def.get("reason", "")
                tag_key, tag_expr = next(iter(condition.items()), (None, None))

                if tag_key and tag_key in tags:
                    tag_val = str(tags[tag_key])
                    if "!=" in tag_expr:
                        expected = tag_expr.split("!=")[-1].strip()
                        if tag_val == expected:
                            continue
                    elif tag_val != tag_expr.strip():
                        continue

                edge["severity"] = {
                    "deny": "high",
                    "flag": "medium",
                    "audit": "info"
                }.get(rule_type, edge["severity"])

                edge["message"] = reason
                print(f"⚠️ {rule_type.upper()} triggered: {source} ➞ {target} — {reason}")

        result_path.append(edge)

    return [{"path": result_path}]

def orchestrate_security_scan(profile_path, folder, show_audit=True):
    results = trigger_scan(
        folder,
        profile_path=profile_path,
        policy_path="configs/policies/access_rules.yaml"
    )

    if not results:
        print("⚠️ No scan results returned.")
        return {}, None

    # 🔍 Run graph queries before render
    severity_counts = count_edges_by_severity(results)
    top_violations = get_edge_messages(results)
    high_risk = find_paths_by_severity(results, "high")

    # 📊 Render the annotated graph
    summary, image_path = render_annotated_graph(results, show_audit=show_audit)

    summary.update({
        "severity_breakdown": severity_counts,
        "violations": top_violations,
        "high_risk_count": len(high_risk)
    })

    print("📊 IAM graph and insights ready.")
    return summary, image_path