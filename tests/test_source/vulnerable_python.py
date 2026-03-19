"""
Intentionally vulnerable Python code for scanner validation.
DO NOT use in production. Every function here is unsafe.
"""
import os
import json
import subprocess
import unicodedata


# wifi_cmd: Command injection via os.system()
def connect_wifi_system(ssid):
    os.system(f"nmcli dev wifi connect '{ssid}'")


# wifi_cmd: Command injection via os.popen()
def scan_wifi_popen(ssid):
    os.popen(f"iwlist wlan0 scan | grep {ssid}")


# wifi_cmd: Command injection via subprocess with shell=True
def connect_subprocess(ssid):
    subprocess.call(f"nmcli dev wifi connect {ssid}", shell=True)


# wifi_serial: JSON injection via SSID
def save_config_json(ssid):
    config = f'{{"ssid": "{ssid}"}}'
    with open("/tmp/wifi.json", "w") as f:
        f.write(config)


# wifi_serial: SQL injection via SSID
def save_to_db(ssid, cursor):
    cursor.execute(f"INSERT INTO networks (ssid) VALUES ('{ssid}')")


# wifi_path: Path traversal via SSID
def log_ssid_to_file(ssid):
    log_path = f"/var/log/wifi/{ssid}.log"
    with open(log_path, "a") as f:
        f.write("connected\n")


# wifi_enc: Encoding normalization bypass
def check_and_normalize(ssid):
    import re
    if re.match(r'^[^;|$`&]+$', ssid):
        ssid = unicodedata.normalize('NFKC', ssid)
        os.system(f"echo {ssid}")


# wifi_esc: Terminal escape in logging
def log_ssid_terminal(ssid):
    print(f"Discovered AP: {ssid}")


# wifi_nosql: MongoDB query injection
def find_network(ssid, db):
    query = json.loads('{"ssid": ' + ssid + '}')
    db.networks.find(query)
