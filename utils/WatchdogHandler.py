"""
CREDIT

Context manager for basic directory watching.
   - <https://github.com/gorakhargosh/watchdog/issues/346>.
"""

from typing import Optional
from datetime import datetime, timedelta
from pathlib import Path
from time import sleep
import threading
import time
from typing import Callable
from utils.Logger import Log
import toml
import zipfile, io

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from utils.Scanner import scan
from utils.integration.Discord import webhook
from utils.integration.AI import ai_analyse

t = time.time()

with open("config.toml", "r") as f:
    data = toml.loads(f.read())

paths = data['DETECTION']['watchdogPath']
if not isinstance(paths, list):
    paths = [paths]

ignore_paths = data['DETECTION'].get('watchdogIgnorePath', [])
ignore_files = data['DETECTION'].get('watchdogIgnoreFile', [])


def s(input_dict):
    fields = []
    for filename, matches in input_dict.items():
        for match in matches:
            rule_name = match.rule
            details = []
            for s in match.strings:
                for instance in s.instances:
                    offset = instance.offset
                    identifier = s.identifier
                    matched_data = instance.matched_data
                    try:
                        # Try decoding as UTF-8, replace errors
                        matched_str = matched_data.decode('utf-8', 'replace')
                    except Exception:
                        matched_str = repr(matched_data) # fallback to repr for non-text data
                    
                    # Sanitize for Discord
                    matched_str = matched_str.replace('`', '\`')
                    if len(matched_str) > 80:
                        matched_str = matched_str[:77] + '...'

                    details.append(
                        f"Offset: `{instance.offset}`, "
                        f"ID: `{s.identifier}`, "
                        f"Matched: `{matched_str}`"
                    )
            if details:
                fields.append({
                    "name": f"Rule: {match.rule} (in {filename})",
                    "value": "\n".join(f"- {d}" for d in details)
                })
    return fields


def c(d):
    count = 0
    for key in d:
        if isinstance(d[key], list):
            count += len(d[key])
    return count


def analysis(event_path: str, file_content: str, flag_type: str, event_dest_path: str = None):
    """
    Process file events in a separate thread.
    This function scans the file content, and if flagged,
    performs AI analysis and sends a webhook notification.
    """
    # Notify plugins that scan is starting
    for plugin in ModifiedFileHandler.active_plugins:
        try:
            if hasattr(plugin, 'on_scan') and callable(plugin.on_scan):
                plugin.on_scan(event_path, file_content, flag_type)
        except Exception as e:
            Log.e(f"{plugin.name}: {str(e)}")
    

    # for .jar detection 2025-07-02
    results = {}
    try:
        path_to_check = event_dest_path if event_dest_path else event_path
        
        if path_to_check.endswith(".jar"):
            all_matches = {}
            with open(path_to_check, "rb") as f:
                zip_memfile = io.BytesIO(f.read())

            with zipfile.ZipFile(zip_memfile) as z:
                for name in z.namelist():
                    if name.endswith(".class"):
                        with z.open(name) as class_file:
                            class_data = class_file.read()
                            scan_result = scan(class_data)
                            if scan_result and scan_result[0]:
                                for rule, matches in scan_result[0].items():
                                    if rule not in all_matches:
                                        all_matches[rule] = []
                                    all_matches[rule].extend(
                                        [f"'{match}' in {name}" for match in matches]
                                    )
            
            if all_matches:
                results = (all_matches, None)
            else:
                results = (False, None)
        else: 
            results = scan(file_content)
    except Exception as e:
        Log.e(f"Error scanning file {event_path}: {str(e)}")
        results = (False, {"error": str(e)})
    # Notify plugins that scan is completed
    for plugin in ModifiedFileHandler.active_plugins:
        try:
            if hasattr(plugin, 'on_scan_completed') and callable(plugin.on_scan_completed):
                plugin.on_scan_completed(event_path, file_content, flag_type, results)
        except Exception as e:
            Log.e(f"{plugin.name}: {str(e)}")
     
    try:
        if results[0]:
            Log.s(f"Flagged {event_path} {results}")
            analysis_result = ai_analyse(file_content)
            
            # Notify plugins that AI analysis is completed
            for plugin in ModifiedFileHandler.active_plugins:
                try:
                    if hasattr(plugin, 'on_ai_analysis_completed') and callable(plugin.on_ai_analysis_completed):
                        plugin.on_ai_analysis_completed(event_path, file_content, flag_type, results, analysis_result)
                except Exception as e:
                    Log.e(f"{plugin.name}: {str(e)}")
            
            msg = f"Total Flagged Pattern: {str(c(results[0]))}\n\n{analysis_result}"
            webhook(event_path, s(results[0]), msg)
            
            for plugin in ModifiedFileHandler.active_plugins:
                try:
                    if hasattr(plugin, 'on_detected') and callable(plugin.on_detected):
                        plugin.on_detected(event_path, file_content, flag_type, results)
                except Exception as e:
                    Log.e(f"{plugin.name}: {str(e)}")
    except: pass


class DirWatcher:
    """Run a function when a directory changes."""

    min_cooldown = 0.1

    def __init__(
        self,
        watch_dir: Path,
        interval: float = 0.2,
        cooldown: float = 0.1,
        plugins=None
    ):
        if interval < self.min_cooldown:
            raise ValueError(
                f"Interval of {interval} seconds is less than the minimum cooldown of "
                f"{self.min_cooldown} seconds."
            )
        if cooldown < self.min_cooldown:
            raise ValueError(
                f"Cooldown of {cooldown} seconds is less than the minimum cooldown of "
                f"{self.min_cooldown} seconds."
            )
        self.watch_dir = watch_dir
        self.interval = interval
        self.cooldown = cooldown
        # Store the plugins passed from PluginHandler
        self.plugins = plugins or []

    def __enter__(self):
        self.observer = Observer()
        self.observer.schedule(
            ModifiedFileHandler(scan, self.cooldown, self.plugins), self.watch_dir, recursive=True
        )

        Log.s(data['LANGUGAE']['english']['novelStarted'].format(str(round(time.time() - t, 5))))
        self.observer.start()
        return self

    def __exit__(self, exc_type: Optional[Exception], *_) -> bool:
        if exc_type and exc_type is KeyboardInterrupt:
            self.observer.stop()
            handled_exception = True
        elif exc_type:
            handled_exception = False
        else:
            handled_exception = True
        self.observer.join()
        return handled_exception

    def run(self):
        """Check for changes on an interval."""
        try:
            while True:
                sleep(self.interval)
        except KeyboardInterrupt:
            self.observer.stop()
            exit()
        exit()


class ModifiedFileHandler(FileSystemEventHandler):
    """Handle modified files using threading for processing."""
    
    # Class variable to store plugins for access from the analysis function
    active_plugins = []

    def __init__(self, func: Callable[[FileSystemEvent], None], cooldown: float, plugins=None):
        self.cooldown = timedelta(seconds=cooldown)
        self.triggered_time = datetime.min
        self.plugins = plugins or []
        # Update the class variable with the current plugins
        ModifiedFileHandler.active_plugins = self.plugins

    def trigger(self, event_type, event):
        """Notify all plugins about the event"""
        for plugin in self.plugins:
            try:
                method = getattr(plugin, f"on_{event_type}", None)
                if method and callable(method):
                    # Call the plugin's event handler method
                    method(event.src_path)
            except Exception as e:
                Log.e(f"Error calling plugin {plugin.name} for {event_type} event: {str(e)}")

    def ignore_event(self, event: FileSystemEvent) -> bool:
        for ignore_path in ignore_paths:
            if event.src_path.startswith(ignore_path):
                return True
        for ignore_file in ignore_files:
            if event.src_path.endswith(ignore_file):
                return True
        if event.src_path == ".":
            return True
        return False

    def on_any_event(self, event: FileSystemEvent):
        if self.ignore_event(event):
            self.trigger("any_event", event)
            return True

    def on_modified(self, event: FileSystemEvent):
        if self.ignore_event(event):
            return
        if (datetime.now() - self.triggered_time) > self.cooldown:
            try:
                if event.src_path.endswith(".jar"):
                    src = ""
                else:
                    with open(event.src_path, "r",encoding="utf-8") as f:
                        src = f.read()
                if data['LOGS']['fileModified']:
                    Log.v(f"FILE MODF | {event.src_path}")

                threading.Thread(target=analysis, args=(event.src_path, src, "modification")).start()

                self.trigger("modified", event)
                self.triggered_time = datetime.now()
            except Exception as e:
                # Log.e(str(e))
                pass

    def on_moved(self, event: FileSystemEvent):
        if self.ignore_event(event):
            return
        if (datetime.now() - self.triggered_time) > self.cooldown:
            try:
                if data['LOGS']['fileMoved']:
                    Log.v(f"FILE MOV | {event.src_path} > {event.dest_path}")

                if event.src_path.endswith(".jar"):
                    src = ""
                else:
                    with open(event.src_path, "r") as f:
                        src = f.read()
                threading.Thread(target=analysis, args=(event.src_path, src, "moved", event.dest_path)).start()

                self.trigger("moved", event)
                self.triggered_time = datetime.now()
            except Exception:
                pass

    def on_deleted(self, event: FileSystemEvent):
        if self.ignore_event(event):
            return
        if (datetime.now() - self.triggered_time) > self.cooldown:
            try:
                if data['LOGS']['fileDeleted']:
                    Log.v(f"FILE DEL | {event.src_path}")

                self.trigger("deleted", event)
                self.triggered_time = datetime.now()
            except Exception:
                pass

    def on_created(self, event: FileSystemEvent):
        if self.ignore_event(event):
            return
        if (datetime.now() - self.triggered_time) > self.cooldown:
            try:
                if event.is_directory:
                    return
                else:
                    if data['LOGS']['fileCreated']:
                        Log.v(f"file created: {event.src_path}")
                if event.src_path.endswith(".jar"):
                    src = ""
                else:
                    with open(event.src_path, "r") as f:
                        src = f.read()
                    threading.Thread(target=analysis, args=(event.src_path, src, "creation")).start()

                    self.trigger("created", event)
                    self.triggered_time = datetime.now()
            except Exception:
                pass

