import time, importlib, toml, os

from utils.Logger import Log
from utils.WatchdogHandler import DirWatcher

class PluginHandler:
    def __init__(self):
        self.t = time.time()
        plugin_dir = './plugins'
        if not os.path.isdir(plugin_dir):
            Log.e(f"{plugin_dir} not found. Exiting...")
            raise FileNotFoundError(f"Make sure '{plugin_dir}' is existing as plugin dir.")
        self._plugins = []
        for file in os.listdir(plugin_dir):
            if file.endswith('.py'):
                path = os.path.join(plugin_dir, file)
                try:
                    spec = importlib.util.spec_from_file_location("plugin", path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self._plugins.append(module.Plugin())
                except (ImportError, AttributeError, SyntaxError) as e:
                    Log.e(f"[PLUGIN] \"{file}\": {e}")
        with open("config.toml", "r") as f:
            self.data = toml.loads(f.read())
        self.path = self.data['DETECTION']['watchdogPath']

    def app_run(self):
        for plugin in self._plugins:
            try:
                Log.v(f"[PLUGIN] Loading \"{plugin.name}\" v{plugin.version}\"")
                plugin.on_start()
            except Exception as e: 
                Log.e(f"[PLUGIN] \"{plugin.name}\": {str(e)}")

        with DirWatcher(self.path, interval=1, plugins=self._plugins) as watcher:
            watcher.run()

        Log.s(self.data['LANGUGAE']['english']['novelStarted'].format(str(round(time.time() - self.t, 1))))

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            exit()
