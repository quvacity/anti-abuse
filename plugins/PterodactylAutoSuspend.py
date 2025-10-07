from utils.Logger import Log
import toml, requests, os
class Plugin:

    def __init__(self):
        self.version = '1.0.0'
        self.name = 'Pterodactyl Auto Suspend'
        self.config = {}

    def on_start(self, *args, **kwargs):
        with open("config.toml", "r") as f:
            self.config = toml.loads(f.read())['PLUGINS']['PterodactylAutoSuspend']
            # Log.s(self.config)

    def on_detected(self, *args, **kwargs):
        # Log.s("detected ")
        uuid = args[0].split(self.config['path'])[1].split("\\" if os.name == "nt" else "/")[1]
        id_ = requests.get(f"{self.config['hostname']}/api/application/servers?filter[uuid]={uuid}", headers={"Authorization": f"Bearer {self.config['api_key']}"}) 
        if id_.status_code == 200:
            id = id_.json()['data'][0]['attributes']['id']
        else:
            Log.e("Failed to get server id of " + str(uuid))
            return
        
        d = requests.post(f"{self.config['hostname']}/api/application/servers/{id}/suspend", headers={"Authorization": f"Bearer {self.config['api_key']}"})
        if(d.status_code == 204):
            Log.s("Suspended: "+str(uuid))
        else:
            Log.e("Failed to suspend "+str(uuid))
            Log.e(d.text)
