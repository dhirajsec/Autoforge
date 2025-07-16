import os
import json
import importlib

def load_config(path="config.json"):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "enable_public_access_check": True,
            "enable_https_check": True,
            "enable_replication_check": True,
            "strict_mode": False
        }

def scan_terraform_file(file_path, config=None):
    if config is None:
        config = load_config()

    results = []
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for rule_file in os.listdir("rules"):
        if rule_file.endswith(".py"):
            module_name = rule_file[:-3]
            rule_module = importlib.import_module(f"rules.{module_name}")
            rule_results = rule_module.check(lines, config)
            results.extend(rule_results)

    if not results:
        results.append({
            "message": "✅ No compliance issues detected",
            "rule": "All Clear",
            "plugin": "base",
            "severity": "none",
            "category": "compliance"
        })

    return results




def scan_folder(folder_path, config=None):
    summary = {}

    if not os.path.exists(folder_path):
        return {"error": f"❌ Folder not found: {folder_path}"}

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith(".tf"):
                full_path = os.path.join(root, filename)
                scan_result = scan_terraform_file(full_path,config=config)
                relative_path = os.path.relpath(full_path, folder_path)
                summary[relative_path] = scan_result

    return summary
