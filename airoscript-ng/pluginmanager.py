# pluginmanager.py
from collections import defaultdict


plugins = defaultdict(list)
def register(*events):
    """ This decorator is to be used for registering a function as a plugin for
        a specific event or list of events.
    """
    def registered_plugin(funct):
        for event in events:
            plugins[event].append(funct)
        return funct
    return registered_plugin


def trigger_event(event, *args, **kwargs):
    """ Call this function to trigger an event. It will run any plugins that
        have registered themselves to the event. Any additional arguments or
        keyword arguments you pass in will be passed to the plugins.
    """
    for plugin in plugins[event]:
        plugin(*args, **kwargs)


def load_plugins(config_file):
    """ This reads a config file of a list of plugins to load. It ignores
        empty lines or lines beginning with a hash mark (#). It is so plugin
        imports are more dynamic and you don't need to continue appending
        import statements to the top of a file.
    """
    with open(config_file, "r") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("#") or line == "":
                continue
            __import__(line,  globals(), locals(), [], -1)
