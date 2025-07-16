# tfplan_scanner.py

import json

def load_tfplan(plan_path):
    with open(plan_path, "r", encoding="utf-8") as f:
        return json.load(f)

def get_resources(plan_json):
    resources = []
    planned = plan_json.get("planned_values", {}).get("root_module", {})

    # Get top-level resources
    for res in planned.get("resources", []):
        resources.append(extract_resource(res))

    # Get child module resources
    for mod in planned.get("child_modules", []):
        for res in mod.get("resources", []):
            resources.append(extract_resource(res))

    return resources

def extract_resource(res):
    return {
        "type": res.get("type"),
        "name": res.get("name"),
        "values": res.get("values", {}),
        "address": res.get("address")
    }