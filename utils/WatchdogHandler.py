"""
CREDIT

Context manager for basic directory watching.
   - <https://github.com/gorakhargosh/watchdog/issues/346>.
"""

from typing import Optional, Callable
from datetime import datetime, timedelta
from pathlib import Path
from time import sleep
import threading
import time
from utils.Logger import Log
import toml
import zipfile, io
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from utils.Scanner import scan
from utils.integration.Discord import webhook
from utils.integration.AI import ai_analyse

t = time.time()

with open("config.toml", "r", encoding="utf-8") as f:
    data = toml.loads(f.read())

paths = data['DETECTION']['watchdogPath']
if not isinstance(paths, list):
    paths = [paths]

ignore_paths = data['DETECTION'].get('watchdogIgnorePath', [])
ignore_files = data['DETECTION'].get('watchdogIgnoreFile', [])


def s(input_dict):
    """
    Normalize/format scan results for webhook.
    Supports a few shapes:
      - { filename: [ match_obj, ... ] } (YARA-like objects)
      - { rule_name: [ "matched text in <entry>", ... ] } (string-based)
    Returns list of Discord embed-style fields: {"name":..., "value":...}
    """
    fields = []

    if not input_dict:
        return fields

    for key, matches in input_dict.items():
        if not matches:
            continue

        # If matches look like objects with .rule or .strings, treat as object-based
        first = matches[0]
        is_obj_like = hasattr(first, "rule") or hasattr(first, "strings") or hasattr(first, "meta")

        if is_obj_like:
            # key is likely filename
            details = []
            for match in matches:
                try:
                    rule_name = getattr(match, "rule", "<unknown-rule>")
                except Exception:
                    rule_name = "<unknown-rule>"

                # gather string instances if present
                try:
                    for s_item in getattr(match, "strings", []):
                        for instance in getattr(s_item, "instances", []):
                            try:
                                matched_data = getattr(instance, "matched_data", b"")
                                if isinstance(matched_data, (bytes, bytearray)):
                                    matched_str = matched_data.decode("utf-8", "replace")
                                else:
                                    matched_str = str(matched_data)
                            except Exception:
                                matched_str = repr(getattr(instance, "matched_data", "<non-text>"))

                            matched_str = matched_str.replace('`', '\\`')
                            if len(matched_str) > 80:
                                matched_str = matched_str[:77] + '...'

                            details.append(
                                f"Offset: `{getattr(instance,'offset','?')}`, "
                                f"ID: `{getattr(s_item,'identifier','?')}`, "
                                f"Matched: `{matched_str}`"
                            )
                except Exception:
                    # fallback: represent the match object minimally
                    details.append(f"Rule: `{rule_name}` - {repr(match)}")

            if details:
                fields.append({
                    "name": f"{key}",
                    "value": "\n".join(f"- {d}" for d in details)
                })
        else:
            # matches are simple strings (e.g. "'<match>' in path/to/entry" or reprs)
            details = []
            for m in matches:
                try:
                    mm = str(m).replace('`', '\\`')
                    if len(mm) > 150:
                        mm = mm[:147] + "..."
                    details.append(mm)
                except Exception:
                    details.append(repr(m))
            if details:
                fields.append({
                    "name": f"{key}",
                    "value": "\n".join(f"- {d}" for d in details)
                })

    return fields


def c(d):
    """Count number of matches in a dict of lists"""
    count = 0
    for key in d:
        val = d[key]
        if isinstance(val, list):
            count += len(val)
    return count


def analysis(event_path: str, file_content, flag_type: str, event_dest_path: str = None):
    """
    Process file events in a separate thread.

    - event_path: original path on filesystem
    - file_content: for non-jar, bytes or str; for jar events will be None (we'll read from disk)
    - flag_type: string ("creation", "modification", "moved", ...)
    - event_dest_path: optional destination path for moved events
    """
    # Notify plugins that scan is starting
    for plugin in ModifiedFileHandler.active_plugins:
        try:
            if hasattr(plugin, 'on_scan') and callable(plugin.on_scan):
                plugin.on_scan(event_path, file_content, flag_type)
        except Exception as e:
            Log.e(f"{plugin.name}: {str(e)}")

    results = {}
    try:
        path_to_check = event_dest_path if event_dest_path else event_path

        if path_to_check.endswith(".jar"):
            all_matches = {}   # rule_name -> [ "matched description in <entry>", ... ]
            try:
                # Read jar bytes from disk
                with open(path_to_check, "rb") as f:
                    zip_memfile = io.BytesIO(f.read())

                with zipfile.ZipFile(zip_memfile) as z:
                    for name in z.namelist():
                        # skip directory entries
                        if name.endswith('/'):
                            continue

                        try:
                            with z.open(name) as entry:
                                entry_bytes = entry.read()
                        except Exception as e:
                            Log.e(f"Failed reading entry {name} inside {path_to_check}: {e}")
                            continue

                        # Try to scan the entry bytes. scan() might accept bytes or expect text.
                        try:
                            scan_result = scan(entry_bytes)
                        except Exception:
                            # fallback: try to decode as utf-8 and scan text
                            try:
                                entry_text = entry_bytes.decode("utf-8", "replace")
                                scan_result = scan(entry_text)
                            except Exception as e_scan:
                                Log.e(f"scan() error for {name} inside {path_to_check}: {str(e_scan)}")
                                scan_result = (False, {"error": str(e_scan)})

                        if scan_result and scan_result[0]:
                            for rule, matches in scan_result[0].items():
                                if rule not in all_matches:
                                    all_matches[rule] = []
                                for m in matches:
                                    if isinstance(m, str):
                                        all_matches[rule].append(f"{m} (in {name})")
                                    else:
                                        try:
                                            all_matches[rule].append(f"{repr(m)} (in {name})")
                                        except Exception:
                                            all_matches[rule].append(f"<match> (in {name})")

                if all_matches:
                    results = (all_matches, None)
                else:
                    results = (False, None)

            except Exception as e:
                Log.e(f"Error scanning jar {path_to_check}: {str(e)}")
                results = (False, {"error": str(e)})

        else:
            # Non-jar file: file_content may be bytes or str
            # If file_content is bytes, prefer passing bytes to scan; if scan fails, fallback to text.
            try:
                scan_result = None
                if isinstance(file_content, (bytes, bytearray)):
                    try:
                        scan_result = scan(file_content)
                    except Exception:
                        try:
                            text = file_content.decode("utf-8", "replace")
                            scan_result = scan(text)
                        except Exception as e_scan:
                            Log.e(f"scan() error for {path_to_check}: {str(e_scan)}")
                            scan_result = (False, {"error": str(e_scan)})
                else:
                    # assume string
                    try:
                        scan_result = scan(file_content)
                    except Exception:
                        # try encoding to bytes
                        try:
                            scan_result = scan(file_content.encode("utf-8"))
                        except Exception as e_scan:
                            Log.e(f"scan() error for {path_to_check}: {str(e_scan)}")
                            scan_result = (False, {"error": str(e_scan)})

                results = scan_result
            except Exception as e:
                Log.e(f"Error scanning file {event_path}: {str(e)}")
                results = (False, {"error": str(e)})

    except Exception as e:
        Log.e(f"Error in analysis for {event_path}: {str(e)}")
        results = (False, {"error": str(e)})

    # Notify plugins that scan is completed
    for plugin in ModifiedFileHandler.active_plugins:
        try:
            if hasattr(plugin, 'on_scan_completed') and callable(plugin.on_scan_completed):
                plugin.on_scan_completed(event_path, file_content, flag_type, results)
        except Exception as e:
            Log.e(f"{plugin.name}: {str(e)}")

    try:
        if results and results[0]:
            Log.s(f"Flagged {event_path} {results}")
            # Prepare content for AI analysis:
            # Prefer a decoded text if available; else produce a small summary of matches.
            try:
                if isinstance(file_content, str) and file_content:
                    analysis_result = ai_analyse(file_content)
                elif isinstance(file_content, (bytes, bytearray)):
                    # attempt to decode a reasonable prefix to give context
                    try:
                        sample = file_content[:4096].decode("utf-8", "replace")
                        analysis_result = ai_analyse(sample)
                    except Exception:
                        # fallback: make summary from matches
                        short_summary = []
                        for rule, matches in results[0].items():
                            short_summary.append(f"{rule}: {len(matches)} hits")
                            if len(matches) <= 3:
                                short_summary.extend(matches[:3])
                        analysis_result = ai_analyse("\n".join(short_summary))
                else:
                    short_summary = []
                    for rule, matches in results[0].items():
                        short_summary.append(f"{rule}: {len(matches)} hits")
                        if len(matches) <= 3:
                            short_summary.extend(matches[:3])
                    analysis_result = ai_analyse("\n".join(short_summary))
            except Exception as e:
                Log.e(f"AI analysis failed for {event_path}: {str(e)}")
                analysis_result = "AI analysis failed."

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
    except Exception:
        # swallow to ensure thread doesn't crash silently
        pass


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

    def _read_file_bytes_safe(self, path: str):
        """Try to read file bytes; return (bytes or None)"""
        try:
            with open(path, "rb") as f:
                return f.read()
        except Exception as e:
            Log.e(f"Failed to read file {path}: {e}")
            return None

    def on_modified(self, event: FileSystemEvent):
        if self.ignore_event(event):
            return
        if (datetime.now() - self.triggered_time) > self.cooldown:
            try:
                if event.src_path.endswith(".jar"):
                    src_bytes = None
                else:
                    src_bytes = self._read_file_bytes_safe(event.src_path)

                # Prepare a text version if possible (for logging / AI)
                src_text = None
                if isinstance(src_bytes, (bytes, bytearray)):
                    try:
                        src_text = src_bytes.decode("utf-8", "replace")
                    except Exception:
                        src_text = None

                if data['LOGS']['fileModified']:
                    Log.v(f"FILE MODF | {event.src_path}")

                threading.Thread(target=analysis, args=(event.src_path, src_bytes if src_bytes is not None else src_text, "modification")).start()

                self.trigger("modified", event)
                self.triggered_time = datetime.now()
            except Exception as e:
                Log.e(str(e))
                pass

    def on_moved(self, event: FileSystemEvent):
        if self.ignore_event(event):
            return
        if (datetime.now() - self.triggered_time) > self.cooldown:
            try:
                if data['LOGS']['fileMoved']:
                    Log.v(f"FILE MOV | {event.src_path} > {event.dest_path}")

                if event.src_path.endswith(".jar"):
                    src_bytes = None
                else:
                    src_bytes = self._read_file_bytes_safe(event.src_path)

                src_text = None
                if isinstance(src_bytes, (bytes, bytearray)):
                    try:
                        src_text = src_bytes.decode("utf-8", "replace")
                    except Exception:
                        src_text = None

                threading.Thread(target=analysis, args=(event.src_path, src_bytes if src_bytes is not None else src_text, "moved", event.dest_path)).start()

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
                    src_bytes = None
                else:
                    src_bytes = self._read_file_bytes_safe(event.src_path)

                src_text = None
                if isinstance(src_bytes, (bytes, bytearray)):
                    try:
                        src_text = src_bytes.decode("utf-8", "replace")
                    except Exception:
                        src_text = None

                threading.Thread(target=analysis, args=(event.src_path, src_bytes if src_bytes is not None else src_text, "creation")).start()

                self.trigger("created", event)
                self.triggered_time = datetime.now()
            except Exception:
                pass
