import yaml

def load_yaml_policies(path="configs/policies/access_rules.yaml"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            policies = yaml.safe_load(f)
    except Exception as e:
        print("❌ Failed to load YAML policies:", e)
        return []

    return policies.get("rules", [])