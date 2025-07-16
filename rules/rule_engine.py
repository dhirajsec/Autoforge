import os
import importlib
import inspect

from plugin_system import RulePlugin, register_plugin, get_all_plugins
from rules.decorators import suppressible

RULES_DIR = "rules"

def discover_plugins():
    for file in os.listdir(RULES_DIR):
        if file.endswith(".py") and not file.startswith("__") and file != "decorators.py":
            module_name = f"{RULES_DIR}.{file[:-3]}"
            try:
                module = importlib.import_module(module_name)

                # Find a scan() function
                for name, func in inspect.getmembers(module, inspect.isfunction):
                    if name == "scan":
                        # Infer rule ID from result
                        rule_id = infer_rule_id(func)
                        wrapped_func = suppressible(rule_id)(func)

                        plugin = RulePlugin(
                            id=rule_id,
                            func=wrapped_func,
                            severity=infer_severity(func),
                            category="Uncategorized",  # We can make this dynamic later
                            description=f"{rule_id} auto-loaded from {file}"
                        )

                        register_plugin(plugin)
            except Exception as e:
                print(f"⚠️ Failed to load plugin from {file}: {e}")

def infer_rule_id(func):
    try:
        dummy = func("dummy.tf", "", {})
        if dummy and isinstance(dummy, list):
            return dummy[0].get("rule", "unknown_rule")
    except:
        pass
    return "unknown_rule"

def infer_severity(func):
    try:
        dummy = func("dummy.tf", "", {})
        if dummy and isinstance(dummy, list):
            return dummy[0].get("severity", "Medium")
    except:
        pass
    return "Medium"

def read_tf_files(folder):
    tf_files = []
    for root, _, files in os.walk(folder):
        for file in files:
            if file.endswith(".tf"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    tf_files.append((path, f.read()))
    return tf_files

def run_scan(folder, config):
    results = []
    tf_files = read_tf_files(folder)

    discover_plugins()
    plugins = get_all_plugins()

    for plugin in plugins:
        for file_name, code in tf_files:
            try:
                results.extend(plugin.scan(file_name, code, config))
            except Exception as e:
                print(f"⚠️ Error scanning with plugin {plugin.id}: {e}")
    return results
