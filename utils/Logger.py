from pystyle import Colors, Colorate
from datetime import datetime
import time, os, sys, inspect


class Log:
    @staticmethod
    def _get_plugin_name():
        try:
            for frame_record in inspect.stack():
                frame = frame_record[0]
                if 'self' in frame.f_locals:
                    instance = frame.f_locals['self']
                    # Check if this is a plugin instance with a name attribute
                    if hasattr(instance, 'name') and 'plugins' in frame.f_globals.get('__file__', ''):
                        return instance.name
        except: return None
        return None

    @staticmethod
    def s(text):  # success
        time_now = datetime.fromtimestamp(time.time()).strftime('%H:%M')
        plugin_name = Log._get_plugin_name()
        
        if plugin_name:
            text = f"[{plugin_name}] {text}"
            
        print(Colors.gray + time_now + " " + Colorate.Horizontal(Colors.green_to_cyan, "SUCCESS", 1) + Colors.gray + " > " + Colors.light_gray + text + Colors.reset)
    
    @staticmethod
    def e(text):  # error
        time_now = datetime.fromtimestamp(time.time()).strftime('%H:%M')
        plugin_name = Log._get_plugin_name()
        
        if plugin_name:
            text = f"[{plugin_name}] {text}"
            
        print(Colors.gray + time_now + " " + Colorate.Horizontal(Colors.red_to_purple, " ERROR ", 1) + Colors.gray + " > " + Colors.light_gray + text + Colors.reset)
    
    @staticmethod
    def v(data):  # verbose
        time_now = datetime.fromtimestamp(time.time()).strftime('%H:%M')
        plugin_name = Log._get_plugin_name()
        
        if plugin_name:
            data = f"[{plugin_name}] {data}"
        
        print(Colors.gray + time_now + " " + Colorate.Horizontal(Colors.blue_to_white, "VERBOSE", 1) + Colors.gray + " > " + Colors.light_gray + data + Colors.reset)