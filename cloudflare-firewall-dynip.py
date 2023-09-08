#!/usr/bin/env python3
#   cloudflare-firewall-dynip.py
#   Summary: Updates Cloudflare firewall rules with your IP
#   Credit: This code is based upon https://github.com/timothymiller/cloudflare-ddns

__version__ = "1.0.0"

import json
import os
import signal
import sys
import threading
import time
import requests

CONFIG_PATH = os.environ.get('CONFIG_PATH', os.getcwd())

class GracefulExit:
    def __init__(self):
        self.kill_now = threading.Event()
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        print("🛑 Stopping main thread...")
        self.kill_now.set()

def getIPs():
    a = None
    aaaa = None
    global ipv4_enabled
    global ipv6_enabled
    if ipv4_enabled:
        try:
            a = requests.get(
                "https://1.1.1.1/cdn-cgi/trace").text.split("\n")
            a.pop()
            a = dict(s.split("=") for s in a)["ip"]
        except Exception:
            global shown_ipv4_warning
            if not shown_ipv4_warning:
                shown_ipv4_warning = True
                print("🧩 IPv4 not detected via 1.1.1.1, trying 1.0.0.1")
            # Try secondary IP check
            try:
                a = requests.get(
                    "https://1.0.0.1/cdn-cgi/trace").text.split("\n")
                a.pop()
                a = dict(s.split("=") for s in a)["ip"]
            except Exception:
                global shown_ipv4_warning_secondary
                if not shown_ipv4_warning_secondary:
                    shown_ipv4_warning_secondary = True
                    print("🧩 IPv4 not detected via 1.0.0.1. Verify your ISP or DNS provider isn't blocking Cloudflare's IPs.")
    if ipv6_enabled:
        try:
            aaaa = requests.get(
                "https://[2606:4700:4700::1111]/cdn-cgi/trace").text.split("\n")
            aaaa.pop()
            aaaa = dict(s.split("=") for s in aaaa)["ip"]
        except Exception:
            global shown_ipv6_warning
            if not shown_ipv6_warning:
                shown_ipv6_warning = True
                print("🧩 IPv6 not detected via 1.1.1.1, trying 1.0.0.1")
            try:
                aaaa = requests.get(
                    "https://[2606:4700:4700::1001]/cdn-cgi/trace").text.split("\n")
                aaaa.pop()
                aaaa = dict(s.split("=") for s in aaaa)["ip"]
            except Exception:
                global shown_ipv6_warning_secondary
                if not shown_ipv6_warning_secondary:
                    shown_ipv6_warning_secondary = True
                    print("🧩 IPv6 not detected via 1.0.0.1. Verify your ISP or DNS provider isn't blocking Cloudflare's IPs.")
    ips = []
    if (a is not None):
        ips.append(a)
    if (aaaa is not None):
        ips.append(aaaa)
    return ips

def commitRecord(ips):
    for option in config["cloudflare"]:
        rule = cf_api("zones/" + option['zone_id'] + "/firewall/rules/" + option['rule_id'], "GET", option)

        if rule is not None:
            filter = rule["result"]["filter"]
            rules = []

            for ip in ips:
                rules.append("(ip.src eq " + ip + ")")

            filterExpression = " or ".join(rules)

            if filter["expression"] != filterExpression:
                print("📡 Updating rule " + str(option['rule_id']) + " with " + filterExpression)
                response = cf_api("zones/" + option['zone_id'] + "/filters/" + filter["id"],
                    "PUT", option, {}, {
                        "id": filter["id"],
                        "expression": filterExpression,
                        "paused": filter["paused"]
                    })
        else:
            print("😡 No firewall rule found, verify your configured zone_id and rule_id")

    return True

def cf_api(endpoint, method, config, headers={}, data=False):
    api_token = config['authentication']['api_token']
    if api_token != '' and api_token != 'api_token_here':
        headers = {
            "Authorization": "Bearer " + api_token, **headers
        }
    else:
        headers = {
            "X-Auth-Email": config['authentication']['api_key']['account_email'],
            "X-Auth-Key": config['authentication']['api_key']['api_key'],
        }
    try:
        if (data == False):
            response = requests.request(
                method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers)
        else:
            response = requests.request(
                method, "https://api.cloudflare.com/client/v4/" + endpoint,
                headers=headers, json=data)

        if response.ok:
            return response.json()
        else:
            print("😡 Error sending '" + method +
                  "' request to '" + response.url + "':")
            print(response.text)
            return None
    except Exception as e:
        print("😡 An exception occurred while sending '" +
              method + "' request to '" + endpoint + "': " + str(e))
        return None

if __name__ == '__main__':
    shown_ipv4_warning = False
    shown_ipv4_warning_secondary = False
    shown_ipv6_warning = False
    shown_ipv6_warning_secondary = False
    ipv4_enabled = True
    ipv6_enabled = True

    if sys.version_info < (3, 5):
        raise Exception("🐍 This script requires Python 3.5+")

    config = None
    try:
        with open(os.path.join(CONFIG_PATH, "config.json")) as config_file:
            config = json.loads(config_file.read())
    except:
        print("😡 Error reading config.json")
        # wait 10 seconds to prevent excessive logging on docker auto restart
        time.sleep(10)

    if config is not None:
        try:
            ipv4_enabled = config["a"]
            ipv6_enabled = config["aaaa"]
        except:
            ipv4_enabled = True
            ipv6_enabled = True
            print("⚙️ Individually disable IPv4 or IPv6 with new config.json options. Read more about it here: https://github.com/timothymiller/cloudflare-ddns/blob/master/README.md")
        try:
            delay = int(config["delay"])
        except:
            delay = 300  # default
            print(
                "⚙️ No config detected for 'delay' - defaulting to 300 seconds (5 minutes)")
        if delay < 30:
            delay = 30  #
            print("⚙️ Delay is too low - defaulting to 30 seconds")
        if (len(sys.argv) > 1):
            if (sys.argv[1] == "--repeat"):
                if ipv4_enabled and ipv6_enabled:
                    print(
                        "🕰️ Updating IPv4 (A) & IPv6 (AAAA) records every " + str(delay) + " seconds")
                elif ipv4_enabled and not ipv6_enabled:
                    print("🕰️ Updating IPv4 (A) records every " +
                          str(delay) + " seconds")
                elif ipv6_enabled and not ipv4_enabled:
                    print("🕰️ Updating IPv6 (AAAA) records every " +
                          str(delay) + " seconds")
                next_time = time.time()
                killer = GracefulExit()
                prev_ips = []
                while True:
                    ips = getIPs()
                    if set(ips) != set(prev_ips):
                        commitRecord(ips)
                        prev_ips = ips
                    if killer.kill_now.wait(delay):
                        break
            else:
                print("❓ Unrecognized parameter '" +
                      sys.argv[1] + "'. Stopping now.")
        else:
            commitRecord(getIPs())