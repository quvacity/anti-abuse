#region Imports
import os, yara, toml
from utils.Logger import Log
#endregion

#region Variables
scanned_files_map = set()
ignored_files = {}
ignored_directories = {}

with open("./config.toml", "r") as f:
    data = toml.loads(f.read())
#endregion

#region scanfile

def scan(src):
    """
    Scan a file with YARA rules and return the matches.

    Args:
     src (str): The file content to be scanned.

    Returns:
     matches[filename], error_message
    """
    matches = {}
    error_messages = {}

    for filename in os.listdir(data['DETECTION']['SignaturePath']):
        if filename.endswith(".yara") or filename.endswith(".yar"): # both are yara extensions ok
            rule_path = os.path.join(data['DETECTION']['SignaturePath'], filename)
            try:
                rules = yara.compile(filepath=rule_path)
                file_matches = rules.match(data=src)
                if file_matches:
                    matches[filename] = file_matches
                    #for match in file_matches:
                    #     Log.v(f"  - Rule: {match.rule}")
            except yara.Error as e:
                Log.e(e)
                error_messages[filename] = e
    return matches, error_messages
#endregion