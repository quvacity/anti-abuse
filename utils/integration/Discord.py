import toml, requests
from utils.Logger import Log

def load_config(file_path):
    """Load configuration from a TOML file."""
    try:
        with open(file_path, "r") as f:
            data = toml.loads(f.read())
            return data
    except FileNotFoundError:
        Log.e(f"Config file {file_path} not found.")
        return None
        Log.e(f"Failed to parse TOML file: {e}")
        return None

def truncate_text(text, limit):
    """Truncate text to the specified character limit with an ellipsis."""
    if len(text) > limit:
        return text[:limit - 3] + "..."  # Truncate and add ellipsis
    return text

def split_text(text, limit):
    """Split text into chunks of a specified character limit."""
    return [text[i:i + limit] for i in range(0, len(text), limit)]

def load_config_values(data):
    """Extract relevant values from the loaded configuration."""
    try:
        enabled = data["INTEGRATION"]["DISCORD"]["enabled"]
        discord_webhook_url = data["INTEGRATION"]["DISCORD"]["webhook_url"]
        ai_integration = data["INTEGRATION"]["AI"]["enabled"]
        truncate_text_flag = data["INTEGRATION"]["DISCORD"].get("truncate_text", True)
        return enabled, discord_webhook_url, ai_integration, truncate_text_flag
    except KeyError as e:
        Log.e(f"Missing key in config: {e}")
        return None, None, None, True

def webhook(file_path, yara_matches, ai=""):
    """Send a webhook to Discord with the given parameters."""
    config_file_path = "./config.toml"
    config_data = load_config(config_file_path)
    if config_data is None:
        Log.e("Failed to load configuration.")
        return

    enabled, discord_webhook_url, ai_integration, truncate_text_flag = load_config_values(config_data)
    if enabled:
        description = ai #if ai_integration and ai else "No Description Provided for this action."

        # Handle truncation or splitting based on config
        if truncate_text_flag:
            description = truncate_text(description, 4092)
        else:
            description_chunks = split_text(description, 4092)

        # Create embeds
        embeds = []
        if truncate_text_flag:
            # Single embed if truncated
            embeds.append({
                "title": f"⚠️ WATCHDOG ALERT ⚠️ - {config_data['machineID']}",
                "description": description,
                "color": 65280,
                "fields": yara_matches,
                "author": {
                    "name": file_path
                },
                "thumbnail": {
                    "url": "https://images-ext-1.discordapp.net/external/ZdQffnnucK3DWYPeokYDWnFPATtlvszVNozmNhOdXBg/https/upload.wikimedia.org/wikipedia/commons/5/59/Empty.png?format=webp&quality=lossless"
                }
            })
        else:
            # Multiple embeds if split
            for idx, chunk in enumerate(description_chunks):
                embeds.append({
                    "title": f"⚠️ WATCHDOG ALERT ⚠️ (Part {idx + 1})",
                    "description": chunk,
                    "color": 65280,
                    "fields": yara_matches if idx == 0 else [],  # Fields only in the first embed
                    "author": {
                        "name": file_path if idx == 0 else None
                    },
                    "thumbnail": {
                        "url": "https://images-ext-1.discordapp.net/external/ZdQffnnucK3DWYPeokYDWnFPATtlvszVNozmNhOdXBg/https/upload.wikimedia.org/wikipedia/commons/5/59/Empty.png?format=webp&quality=lossless"
                    }
                })

        # Construct the payload
        payload = {
            "content": "",
            "embeds": embeds[:10],  # Discord allows a maximum of 10 embeds per payload
            "attachments": []
        }

        try:
            # Send POST request to Discord webhook
            response = requests.post(discord_webhook_url, json=payload)
            response.raise_for_status()  # Raise exception for HTTP errors
            Log.v(f"Report sent to Discord webhook for {file_path}")
        except requests.exceptions.RequestException as e:
            Log.e(f"Report was not sent to Discord webhook, error: {e}")
