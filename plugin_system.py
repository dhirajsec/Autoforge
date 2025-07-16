# plugin_system.py

class RulePlugin:
    def __init__(self, id, func, severity="Medium", category="General", description=""):
        self.id = id
        self.func = func
        self.severity = severity
        self.category = category
        self.description = description

    def scan(self, file_name, code, config):
        return self.func(file_name, code, config)


# Global registry for all loaded plugins
registered_plugins = []

def register_plugin(plugin: RulePlugin):
    registered_plugins.append(plugin)

def get_all_plugins():
    return registered_plugins