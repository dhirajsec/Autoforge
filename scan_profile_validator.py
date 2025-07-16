import os
import json
from datetime import datetime

def is_valid_iso(timestamp):
    try:
        datetime.fromisoformat(timestamp)
        return True
    except ValueError:
        return False

def validate_scan_profiles(config_dir="configs"):
    issues = {}

    for fname in os.listdir(config_dir):
        if fname.endswith(".json"):
            path = os.path.join(config_dir, fname)
            issues[fname] = []

            try:
                with open(path, encoding="utf-8") as f:
                    profile = json.load(f)

                meta = profile.get("meta", {})
                if not meta:
                    issues[fname].append("❌ No metadata block found.")
                    continue

                if not meta.get("comment"):
                    issues[fname].append("⚠️ Missing comment.")
                if not meta.get("tags") or not isinstance(meta.get("tags"), list):
                    issues[fname].append("⚠️ Missing or invalid tags (should be a list).")
                if not meta.get("timestamp"):
                    issues[fname].append("⚠️ Missing timestamp.")
                elif not is_valid_iso(meta["timestamp"]):
                    issues[fname].append("⚠️ Timestamp is not valid ISO format.")

            except Exception as e:
                issues[fname].append(f"❌ Error parsing file: {e}")

    print("\n📊 Metadata Validation Report")
    print("═════════════════════════════")

    for profile, problems in issues.items():
        print(f"\n📁 {profile}")
        if problems:
            for issue in problems:
                print(f" - {issue}")
        else:
            print(" ✅ All metadata checks passed.")

    return issues