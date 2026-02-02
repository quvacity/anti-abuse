[BETA WARNING: SOME FEATURES MIGHT BE NOT RELEASED OR ARE NOT WORKING AS EXPECTED!]

![Novel](/Frame_12x.webp)

# Novel, Anti-Abuse

Introducing Anti-Abuse by Novel.

Anti-Abuse is an ✨ FREE, Open-Sourced radar based on yara rules built for pterodactyl, pelican nodes and docker containers.

## Features
1. Watchdog based real-time monitoring.
2. Easily customizable by [Yara Rule](https://yara.readthedocs.io/en/stable/writingrules.html).
3. Various Integrations(discord webhook, etc).
4. Easy re-check action through AI-Based Analysis.
5. Plugin feature to implement feature on your needs
## Installation

Requirements: python, keyboard, brain

1. Install requirements
```bash
pip install watchdog toml yara-python readchar pystyle
```

2. Configure your config.toml and yara rules
Thirdly run configure config.toml, upload your YARA (.yar and .yara) signatures in /signatures and then finally run RADAR!

```bash
sudo sysctl fs.inotify.max_user_watches=100000
python3 main.py
```

Done! You're now running Anti-Abuse.

# Faq
Q1: You don't know how to write YARA rules?
> Check out [aweasome-yara](https://github.com/InQuest/awesome-yara), this repository contains list of YARA rules collections which you can use. Didn't found what you were looking for? Try creating own YARA rules, take a look at [YARA documentation](https://yara.readthedocs.io/en/latest/index.html)

Q2: We recommend using https://console.groq.com instead of self hosted OLLAMA for better performance!
> We will also underline that https://console.groq.com offers very nice and kind Free Tier which should be enough for small or medium size deployments of Novel

# Reporting security issue or vulnerability 

Please contact us on email:

|Maintainer|Contact|
|----|---|
|Lisa|lisahonkay@gmail.com, `@_lisa_ns_` on discord|
|Lin|contact@who.ad, `@inxtagram` on discord|

Made with ❤️ by `inxtagram` and `_lisa_ns_`, licensed under [GNU GENERAL PUBLIC LICENSE, Version 3](http://lhhomeserver.ddns.net:3000/Lisa_Stuff/RADAR/src/branch/main/LICENSE)
