import json

def load_profile(path="configs/security_baseline.json"):
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        print("⚠️ Failed to load profile:", e)
        return {}

    profile = {
        "deny_paths": raw.get("deny_paths", []),
        "exclude_roles": raw.get("exclude_roles", []),
        "severity_overrides": raw.get("severity_overrides", {}),
        "scope": raw.get("scope", {}),
        "enabled_modules": raw.get("enabled_modules", [])
    }

    return profile