#region Imports
import toml
import requests
from utils.Logger import Log
#endregion

#region Variables
# Load configuration from the config.toml file
with open("./config.toml", "r") as f:
    data = toml.loads(f.read())

enabled = data["INTEGRATION"]["AI"]["enabled"]
generate_endpoint = data["INTEGRATION"]["AI"]["generate_endpoint"]
model_list = data["INTEGRATION"]["AI"]["generate_models"]  
use_groq = data["INTEGRATION"]["AI"]["use_groq"]
groq_api = data["INTEGRATION"]["AI"]["groq_api_token"]
prompt = data["INTEGRATION"]["AI"]["prompt"]

# If Groq is enabled, update the generate endpoint
if use_groq:
    generate_endpoint = "https://api.groq.com/openai/v1/chat/completions"
#endregion

def generate_response(data):
    """Generate a response using the Groq or OLLAMA API."""
    error_messages = []
    for generate_model in model_list:  
        try:
            headers = {
                "Content-Type": "application/json",
            }

            # Add authorization header if using Groq
            if use_groq:
                headers["Authorization"] = f"Bearer {groq_api}"

            # Create payload
            payload = {
                "model": generate_model,
                "temperature": 1,
                "max_completion_tokens": 1024,
                "top_p": 1,
                "stream": False,  
                "stop": None,
            }

            # Conditional message structure for Groq
            if use_groq:
                payload["messages"] = [
                    {
                        "role": "system",
                        "content": f"{prompt}"
                    },
                    {
                        "role": "user",
                        "content": f"```code\n{data}\n```"
                    }
                ]
            else:
                payload["prompt"] = f"Using this data: {data}. Respond to this prompt: {prompt}\n"

            response = requests.post(generate_endpoint, json=payload, headers=headers)
            response.raise_for_status() 
            if use_groq:
                return response.json()["choices"][0]["message"]["content"] + f"\n\n> Used Model: {generate_model}"
            else:
                return response.json()

        except requests.exceptions.RequestException as e:
            Log.e(f"Failed to generate response: {e}")
            Log.e(f"Using model: {generate_model}")
            error_messages.append(f"Model {generate_model} failed: {e}")
            return None
    return f"All models failed to generate response. Errors: {error_messages}"


def ai_analyse(src):
    """Analyze a file and generate a response based on the user's input."""
    if enabled:
        try:

            # Generate response using the file data
            response = generate_response(src)
            print(response)
            if response:
                #Log.s(f"Generated Response: {response}")
                return response
            else:
                return "No AI Description provided for this action; check config.toml maybe?"
        except Exception as e:
            Log.e(f"Unexpected error: {e}")
    else:
        return "No AI Description provided for this action; check config.toml maybe?"
    return None
