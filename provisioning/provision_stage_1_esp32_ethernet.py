#!/usr/bin/python3 -u

import tinkerforge_util as tfutil

tfutil.create_parent_module(__file__, 'provisioning')

import contextlib
from contextlib import contextmanager
from datetime import datetime
import io
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request
from pathlib import Path

from provisioning.tinkerforge.ip_connection import IPConnection, base58encode, base58decode, BASE58

from provisioning.provision_common.provision_common import *

ESP_ETHERNET_DEVICE_ID = 115

def main():
    common_init('/dev/ttyUSB0')

    config = json.loads(Path("provision_stage_1_esp32_ethernet_config.json").read_text())
    esp_ethernet_static_ip = config["esp_ethernet_static_ip"]
    esp_ethernet_static_subnet = config["esp_ethernet_static_subnet"]

    if len(sys.argv) < 2:
        fatal_error("Usage: {} firmware_type".format(sys.argv[0]))

    firmware_type = sys.argv[1]
    if firmware_type not in ["esp32_ethernet", "warp2", "energy_manager", "energy_manager_v2", "smart_energy_broker"]:
        fatal_error("Unknown firmware type {}".format(firmware_type))

    skip_tests = (len(sys.argv) == 3) and (sys.argv[2] == "--skip-tests")

    result = {"start": now()}

    print("Checking ESP state")
    mac_address = check_if_esp_is_sane_and_get_mac()
    print("MAC Address is {}".format(mac_address))
    result["mac"] = mac_address

    set_voltage_fuses, set_block_3, passphrase, uid = get_espefuse_tasks()
    if set_voltage_fuses or set_block_3:
        fatal_error("Fuses are not set. Re-run stage 0!")

    esptool(["--after", "hard_reset", "chip_id"])

    result["uid"] = uid

    if firmware_type == 'warp2':
        ssid = "warp2-" + uid
    elif firmware_type == 'energy_manager':
        ssid = "wem-" + uid
    elif firmware_type == 'energy_manager_v2':
        ssid = "wem2-" + uid
    elif firmware_type == 'smart_energy_broker':
        ssid = "seb-" + uid
    else:
        ssid = "esp32-" + uid

    if not skip_tests:
        run(["sudo", "systemctl", "restart", "NetworkManager.service"])
        run(["sudo", "iw", "reg", "set", "DE"])

        print("Waiting for ESP wifi. Takes about one minute.")
        if not wait_for_wifi(ssid, 90):
            fatal_error("ESP wifi not found after 90 seconds")

        print("Testing ESP Wifi.")
        with wifi(ssid, passphrase):
            req = urllib.request.Request("http://10.0.0.1/ethernet/config_update",
                                        data=json.dumps({"enable_ethernet":True,
                                                        "ip": esp_ethernet_static_ip,
                                                        "gateway":"0.0.0.0",
                                                        "subnet":esp_ethernet_static_subnet,
                                                        "dns":"0.0.0.0",
                                                        "dns2":"0.0.0.0"}).encode("utf-8"),
                                        method='PUT',
                                        headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=10) as f:
                    f.read()
            except Exception as e:
                print(e)
                fatal_error("Failed to set ethernet config!")
            req = urllib.request.Request("http://10.0.0.1/reboot", data=b'null', method='PUT', headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=10) as f:
                    f.read()
            except Exception as e:
                print("Failed to initiate reboot! Attempting to connect via ethernet anyway.")

            result["wifi_test_successful"] = True

        time.sleep(3)
        print(f"Connecting via ethernet to {esp_ethernet_static_ip}", end="")
        for i in range(30):
            start = time.time()
            req = urllib.request.Request(f"http://{esp_ethernet_static_ip}/ethernet/config_update",
                                    data=json.dumps({"enable_ethernet":True,
                                                    "ip":"0.0.0.0",
                                                    "gateway":"0.0.0.0",
                                                    "subnet":"0.0.0.0",
                                                    "dns":"0.0.0.0",
                                                    "dns2":"0.0.0.0"}).encode("utf-8"),
                                    method='PUT',
                                    headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=1) as f:
                    f.read()
                    break
            except:
                pass
            t = max(0, 1 - (time.time() - start))
            time.sleep(t)
            print(".", end="")
        else:
            print("Failed to connect via ethernet!")
            raise Exception("exit 1")
        print(" Connected.")

        req = urllib.request.Request(f"http://{esp_ethernet_static_ip}/info/version")
        try:
            with urllib.request.urlopen(req, timeout=10) as f:
                fw_version = json.loads(f.read().decode("utf-8"))["firmware"].split("-")[0].split("+")[0]
        except Exception as e:
            fatal_error("Failed to read firmware version!")

        if firmware_type in ["warp2", "energy_manager", "energy_manager_v2", "smart_energy_broker"]:
            try:
                with urllib.request.urlopen(f"http://{esp_ethernet_static_ip}/hidden_proxy/enable", timeout=10) as f:
                    f.read()
            except Exception as e:
                print(e)
                fatal_error("Failed to enable hidden_proxy!")

        time.sleep(3)
        ipcon = IPConnection()
        ipcon.connect(esp_ethernet_static_ip, 4223)
        result["ethernet_test_successful"] = True
        print("Connected. Testing bricklet ports")

        test_bricklet_ports(ipcon, ESP_ETHERNET_DEVICE_ID, firmware_type in ["warp2", "energy_manager", "energy_manager_v2", "smart_energy_broker"])
        result["bricklet_port_test_successful"] = True

        led0 = input("Does the status LED blink blue? [y/n]")
        while led0 not in ("y", "n"):
            led0 = input("Does the status LED blink blue? [y/n]")
        result["status_led_test_successful"] = led0 == "y"
        if led0 == "n":
            fatal_error("Status LED does not work")

        # We don't test the IO0 button anymore
        result["io0_test_successful"] = None

        led0_stop = input("Press EN button. Does the status LED stop blinking for some seconds? [y/n]")
        while led0_stop not in ("y", "n"):
            led0_stop = input("Press EN button. Does the status LED stop blinking for some seconds? [y/n]")
        result["enable_test_successful"] = led0_stop == "y"
        if led0_stop == "n":
            fatal_error("EN button does not work")

    result["tests_successful"] = True
    result["end"] = now()

    with open("{}_{}_report_stage_1.json".format(ssid, now().replace(":", "-")), "w") as f:
        json.dump(result, f, indent=4)

    label_success = "n"
    while label_success != "y":
        run(["python3", "print-esp32-label.py", ssid, passphrase, "-c", "3" if firmware_type in ["warp2", "energy_manager", "energy_manager_v2", "smart_energy_broker"] else "1"])
        label_prompt = "Stick one label on the ESP, put ESP{} in the ESD bag. Press n to retry printing the label{}. [y/n]".format(
                " and the other two labels" if firmware_type in ["warp2", "energy_manager", "energy_manager_v2", "smart_energy_broker"] else "",
                "s" if firmware_type in ["warp2", "energy_manager", "energy_manager_v2", "smart_energy_broker"] else "")

        label_success = input(label_prompt)
        while label_success not in ("y", "n"):
            label_success = input(label_prompt)

    if firmware_type == "esp32_ethernet":
        bag_label_success = "n"
        while bag_label_success != "y":
            run(["python3", "../../flash-test/label/print-label.py", "-c", "1", "ESP32 Ethernet Brick", str(ESP_ETHERNET_DEVICE_ID), datetime.datetime.now().strftime('%Y-%m-%d'), uid, fw_version])
            bag_label_prompt = "Stick bag label on bag. Press n to retry printing the label. [y/n]"

            bag_label_success = input(bag_label_prompt)
            while bag_label_success not in ("y", "n"):
                bag_label_success = input(bag_label_prompt)

    print('Done!')

if __name__ == "__main__":
    try:
        main()
        input("Press return to exit. ")
    except FatalError:
        input("Press return to exit. ")
        sys.exit(1)
    except Exception as e:
        traceback.print_exc()
        input("Press return to exit. ")
        sys.exit(1)
