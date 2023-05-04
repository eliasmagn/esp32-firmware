#!/usr/bin/python3 -u

import contextlib
from contextlib import contextmanager
import datetime
import getpass
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
import urllib.request
import csv
import traceback

from tinkerforge.ip_connection import IPConnection, base58encode, base58decode, BASE58
from tinkerforge.bricklet_rgb_led_v2 import BrickletRGBLEDV2




# -*- coding: utf-8 -*-
#############################################################
# This file was automatically generated on 2021-02-03.      #
#                                                           #
# Python Bindings Version 2.1.28                            #
#                                                           #
# If you have a bugfix for this file and want to commit it, #
# please fix the bug in the generator. You can find a link  #
# to the generators git repository on tinkerforge.com       #
#############################################################

#### __DEVICE_IS_NOT_RELEASED__ ####

from collections import namedtuple

from tinkerforge.ip_connection import Device, IPConnection, Error, create_char, create_char_list, create_string, create_chunk_data

GetState = namedtuple('State', ['iec61851_state', 'vehicle_state', 'contactor_state', 'contactor_error', 'charge_release', 'allowed_charging_current', 'error_state', 'lock_state', 'time_since_state_change', 'uptime'])
GetHardwareConfiguration = namedtuple('HardwareConfiguration', ['jumper_configuration', 'has_lock_switch'])
GetLowLevelState = namedtuple('LowLevelState', ['low_level_mode_enabled', 'led_state', 'cp_pwm_duty_cycle', 'adc_values', 'voltages', 'resistances', 'gpio'])
GetMaxChargingCurrent = namedtuple('MaxChargingCurrent', ['max_current_configured', 'max_current_incoming_cable', 'max_current_outgoing_cable', 'max_current_managed'])
GetSPITFPErrorCount = namedtuple('SPITFPErrorCount', ['error_count_ack_checksum', 'error_count_message_checksum', 'error_count_frame', 'error_count_overflow'])
GetIdentity = namedtuple('Identity', ['uid', 'connected_uid', 'position', 'hardware_version', 'firmware_version', 'device_identifier'])

class BrickletEVSE(Device):
    """
    TBD
    """

    DEVICE_IDENTIFIER = 2159
    DEVICE_DISPLAY_NAME = 'EVSE Bricklet'
    DEVICE_URL_PART = 'evse' # internal



    FUNCTION_GET_STATE = 1
    FUNCTION_GET_HARDWARE_CONFIGURATION = 2
    FUNCTION_GET_LOW_LEVEL_STATE = 3
    FUNCTION_SET_MAX_CHARGING_CURRENT = 4
    FUNCTION_GET_MAX_CHARGING_CURRENT = 5
    FUNCTION_CALIBRATE = 6
    FUNCTION_START_CHARGING = 7
    FUNCTION_STOP_CHARGING = 8
    FUNCTION_SET_CHARGING_AUTOSTART = 9
    FUNCTION_GET_CHARGING_AUTOSTART = 10
    FUNCTION_GET_MANAGED = 11
    FUNCTION_SET_MANAGED = 12
    FUNCTION_SET_MANAGED_CURRENT = 13
    FUNCTION_GET_SPITFP_ERROR_COUNT = 234
    FUNCTION_SET_BOOTLOADER_MODE = 235
    FUNCTION_GET_BOOTLOADER_MODE = 236
    FUNCTION_SET_WRITE_FIRMWARE_POINTER = 237
    FUNCTION_WRITE_FIRMWARE = 238
    FUNCTION_SET_STATUS_LED_CONFIG = 239
    FUNCTION_GET_STATUS_LED_CONFIG = 240
    FUNCTION_GET_CHIP_TEMPERATURE = 242
    FUNCTION_RESET = 243
    FUNCTION_WRITE_UID = 248
    FUNCTION_READ_UID = 249
    FUNCTION_GET_IDENTITY = 255

    IEC61851_STATE_A = 0
    IEC61851_STATE_B = 1
    IEC61851_STATE_C = 2
    IEC61851_STATE_D = 3
    IEC61851_STATE_EF = 4
    LED_STATE_OFF = 0
    LED_STATE_ON = 1
    LED_STATE_BLINKING = 2
    LED_STATE_FLICKER = 3
    LED_STATE_BREATHING = 4
    VEHICLE_STATE_NOT_CONNECTED = 0
    VEHICLE_STATE_CONNECTED = 1
    VEHICLE_STATE_CHARGING = 2
    VEHICLE_STATE_ERROR = 3
    CONTACTOR_STATE_AC1_NLIVE_AC2_NLIVE = 0
    CONTACTOR_STATE_AC1_LIVE_AC2_NLIVE = 1
    CONTACTOR_STATE_AC1_NLIVE_AC2_LIVE = 2
    CONTACTOR_STATE_AC1_LIVE_AC2_LIVE = 3
    LOCK_STATE_INIT = 0
    LOCK_STATE_OPEN = 1
    LOCK_STATE_CLOSING = 2
    LOCK_STATE_CLOSE = 3
    LOCK_STATE_OPENING = 4
    LOCK_STATE_ERROR = 5
    ERROR_STATE_OK = 0
    ERROR_STATE_SWITCH = 2
    ERROR_STATE_CALIBRATION = 3
    ERROR_STATE_CONTACTOR = 4
    ERROR_STATE_COMMUNICATION = 5
    JUMPER_CONFIGURATION_6A = 0
    JUMPER_CONFIGURATION_10A = 1
    JUMPER_CONFIGURATION_13A = 2
    JUMPER_CONFIGURATION_16A = 3
    JUMPER_CONFIGURATION_20A = 4
    JUMPER_CONFIGURATION_25A = 5
    JUMPER_CONFIGURATION_32A = 6
    JUMPER_CONFIGURATION_SOFTWARE = 7
    JUMPER_CONFIGURATION_UNCONFIGURED = 8
    CHARGE_RELEASE_AUTOMATIC = 0
    CHARGE_RELEASE_MANUAL = 1
    CHARGE_RELEASE_DEACTIVATED = 2
    CHARGE_RELEASE_MANAGED = 3
    BOOTLOADER_MODE_BOOTLOADER = 0
    BOOTLOADER_MODE_FIRMWARE = 1
    BOOTLOADER_MODE_BOOTLOADER_WAIT_FOR_REBOOT = 2
    BOOTLOADER_MODE_FIRMWARE_WAIT_FOR_REBOOT = 3
    BOOTLOADER_MODE_FIRMWARE_WAIT_FOR_ERASE_AND_REBOOT = 4
    BOOTLOADER_STATUS_OK = 0
    BOOTLOADER_STATUS_INVALID_MODE = 1
    BOOTLOADER_STATUS_NO_CHANGE = 2
    BOOTLOADER_STATUS_ENTRY_FUNCTION_NOT_PRESENT = 3
    BOOTLOADER_STATUS_DEVICE_IDENTIFIER_INCORRECT = 4
    BOOTLOADER_STATUS_CRC_MISMATCH = 5
    STATUS_LED_CONFIG_OFF = 0
    STATUS_LED_CONFIG_ON = 1
    STATUS_LED_CONFIG_SHOW_HEARTBEAT = 2
    STATUS_LED_CONFIG_SHOW_STATUS = 3

    def __init__(self, uid, ipcon):
        """
        Creates an object with the unique device ID *uid* and adds it to
        the IP Connection *ipcon*.
        """
        Device.__init__(self, uid, ipcon, BrickletEVSE.DEVICE_IDENTIFIER, BrickletEVSE.DEVICE_DISPLAY_NAME)

        self.api_version = (2, 0, 2)

        self.response_expected[BrickletEVSE.FUNCTION_GET_STATE] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_GET_HARDWARE_CONFIGURATION] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_GET_LOW_LEVEL_STATE] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_SET_MAX_CHARGING_CURRENT] = BrickletEVSE.RESPONSE_EXPECTED_FALSE
        self.response_expected[BrickletEVSE.FUNCTION_GET_MAX_CHARGING_CURRENT] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_CALIBRATE] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_START_CHARGING] = BrickletEVSE.RESPONSE_EXPECTED_FALSE
        self.response_expected[BrickletEVSE.FUNCTION_STOP_CHARGING] = BrickletEVSE.RESPONSE_EXPECTED_FALSE
        self.response_expected[BrickletEVSE.FUNCTION_SET_CHARGING_AUTOSTART] = BrickletEVSE.RESPONSE_EXPECTED_FALSE
        self.response_expected[BrickletEVSE.FUNCTION_GET_CHARGING_AUTOSTART] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_GET_MANAGED] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_SET_MANAGED] = BrickletEVSE.RESPONSE_EXPECTED_FALSE
        self.response_expected[BrickletEVSE.FUNCTION_SET_MANAGED_CURRENT] = BrickletEVSE.RESPONSE_EXPECTED_FALSE
        self.response_expected[BrickletEVSE.FUNCTION_GET_SPITFP_ERROR_COUNT] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_SET_BOOTLOADER_MODE] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_GET_BOOTLOADER_MODE] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_SET_WRITE_FIRMWARE_POINTER] = BrickletEVSE.RESPONSE_EXPECTED_FALSE
        self.response_expected[BrickletEVSE.FUNCTION_WRITE_FIRMWARE] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_SET_STATUS_LED_CONFIG] = BrickletEVSE.RESPONSE_EXPECTED_FALSE
        self.response_expected[BrickletEVSE.FUNCTION_GET_STATUS_LED_CONFIG] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_GET_CHIP_TEMPERATURE] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_RESET] = BrickletEVSE.RESPONSE_EXPECTED_FALSE
        self.response_expected[BrickletEVSE.FUNCTION_WRITE_UID] = BrickletEVSE.RESPONSE_EXPECTED_FALSE
        self.response_expected[BrickletEVSE.FUNCTION_READ_UID] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE
        self.response_expected[BrickletEVSE.FUNCTION_GET_IDENTITY] = BrickletEVSE.RESPONSE_EXPECTED_ALWAYS_TRUE


        ipcon.add_device(self)

    def get_state(self):
        """
        TODO

        .. versionadded:: 2.0.5$nbsp;(Plugin)
        """
        self.check_validity()

        return GetState(*self.ipcon.send_request(self, BrickletEVSE.FUNCTION_GET_STATE, (), '', 25, 'B B B B B H B B I I'))

    def get_hardware_configuration(self):
        """
        TODO
        """
        self.check_validity()

        return GetHardwareConfiguration(*self.ipcon.send_request(self, BrickletEVSE.FUNCTION_GET_HARDWARE_CONFIGURATION, (), '', 10, 'B !'))

    def get_low_level_state(self):
        """
        TODO
        """
        self.check_validity()

        return GetLowLevelState(*self.ipcon.send_request(self, BrickletEVSE.FUNCTION_GET_LOW_LEVEL_STATE, (), '', 31, '! B H 2H 3h 2I 5!'))

    def set_max_charging_current(self, max_current):
        """
        TODO
        """
        self.check_validity()

        max_current = int(max_current)

        self.ipcon.send_request(self, BrickletEVSE.FUNCTION_SET_MAX_CHARGING_CURRENT, (max_current,), 'H', 0, '')

    def get_max_charging_current(self):
        """
        * Max Current Configured -> set with :func:`Set Max Charging Current`
        * Max Current Incoming Cable -> set with jumper on EVSE
        * Max Current Outgoing Cable -> set with resistor between PP/PE (if fixed cable is used)

        TODO

        .. versionadded:: 2.0.6$nbsp;(Plugin)
        """
        self.check_validity()

        return GetMaxChargingCurrent(*self.ipcon.send_request(self, BrickletEVSE.FUNCTION_GET_MAX_CHARGING_CURRENT, (), '', 16, 'H H H H'))

    def calibrate(self, state, password, value):
        """
        TODO
        """
        self.check_validity()

        state = int(state)
        password = int(password)
        value = int(value)

        return self.ipcon.send_request(self, BrickletEVSE.FUNCTION_CALIBRATE, (state, password, value), 'B I i', 9, '!')

    def start_charging(self):
        """
        TODO
        """
        self.check_validity()

        self.ipcon.send_request(self, BrickletEVSE.FUNCTION_START_CHARGING, (), '', 0, '')

    def stop_charging(self):
        """
        TODO
        """
        self.check_validity()

        self.ipcon.send_request(self, BrickletEVSE.FUNCTION_STOP_CHARGING, (), '', 0, '')

    def set_charging_autostart(self, autostart):
        """
        TODO
        """
        self.check_validity()

        autostart = bool(autostart)

        self.ipcon.send_request(self, BrickletEVSE.FUNCTION_SET_CHARGING_AUTOSTART, (autostart,), '!', 0, '')

    def get_charging_autostart(self):
        """
        TODO
        """
        self.check_validity()

        return self.ipcon.send_request(self, BrickletEVSE.FUNCTION_GET_CHARGING_AUTOSTART, (), '', 9, '!')

    def get_managed(self):
        """
        TODO

        .. versionadded:: 2.0.6$nbsp;(Plugin)
        """
        self.check_validity()

        return self.ipcon.send_request(self, BrickletEVSE.FUNCTION_GET_MANAGED, (), '', 9, '!')

    def set_managed(self, managed, password):
        """
        TODO

        .. versionadded:: 2.0.6$nbsp;(Plugin)
        """
        self.check_validity()

        managed = bool(managed)
        password = int(password)

        self.ipcon.send_request(self, BrickletEVSE.FUNCTION_SET_MANAGED, (managed, password), '! I', 0, '')

    def set_managed_current(self, current):
        """
        TODO

        .. versionadded:: 2.0.6$nbsp;(Plugin)
        """
        self.check_validity()

        current = int(current)

        self.ipcon.send_request(self, BrickletEVSE.FUNCTION_SET_MANAGED_CURRENT, (current,), 'H', 0, '')

    def get_spitfp_error_count(self):
        """
        Returns the error count for the communication between Brick and Bricklet.

        The errors are divided into

        * ACK checksum errors,
        * message checksum errors,
        * framing errors and
        * overflow errors.

        The errors counts are for errors that occur on the Bricklet side. All
        Bricks have a similar function that returns the errors on the Brick side.
        """
        self.check_validity()

        return GetSPITFPErrorCount(*self.ipcon.send_request(self, BrickletEVSE.FUNCTION_GET_SPITFP_ERROR_COUNT, (), '', 24, 'I I I I'))

    def set_bootloader_mode(self, mode):
        """
        Sets the bootloader mode and returns the status after the requested
        mode change was instigated.

        You can change from bootloader mode to firmware mode and vice versa. A change
        from bootloader mode to firmware mode will only take place if the entry function,
        device identifier and CRC are present and correct.

        This function is used by Brick Viewer during flashing. It should not be
        necessary to call it in a normal user program.
        """
        self.check_validity()

        mode = int(mode)

        return self.ipcon.send_request(self, BrickletEVSE.FUNCTION_SET_BOOTLOADER_MODE, (mode,), 'B', 9, 'B')

    def get_bootloader_mode(self):
        """
        Returns the current bootloader mode, see :func:`Set Bootloader Mode`.
        """
        self.check_validity()

        return self.ipcon.send_request(self, BrickletEVSE.FUNCTION_GET_BOOTLOADER_MODE, (), '', 9, 'B')

    def set_write_firmware_pointer(self, pointer):
        """
        Sets the firmware pointer for :func:`Write Firmware`. The pointer has
        to be increased by chunks of size 64. The data is written to flash
        every 4 chunks (which equals to one page of size 256).

        This function is used by Brick Viewer during flashing. It should not be
        necessary to call it in a normal user program.
        """
        self.check_validity()

        pointer = int(pointer)

        self.ipcon.send_request(self, BrickletEVSE.FUNCTION_SET_WRITE_FIRMWARE_POINTER, (pointer,), 'I', 0, '')

    def write_firmware(self, data):
        """
        Writes 64 Bytes of firmware at the position as written by
        :func:`Set Write Firmware Pointer` before. The firmware is written
        to flash every 4 chunks.

        You can only write firmware in bootloader mode.

        This function is used by Brick Viewer during flashing. It should not be
        necessary to call it in a normal user program.
        """
        self.check_validity()

        data = list(map(int, data))

        return self.ipcon.send_request(self, BrickletEVSE.FUNCTION_WRITE_FIRMWARE, (data,), '64B', 9, 'B')

    def set_status_led_config(self, config):
        """
        Sets the status LED configuration. By default the LED shows
        communication traffic between Brick and Bricklet, it flickers once
        for every 10 received data packets.

        You can also turn the LED permanently on/off or show a heartbeat.

        If the Bricklet is in bootloader mode, the LED is will show heartbeat by default.
        """
        self.check_validity()

        config = int(config)

        self.ipcon.send_request(self, BrickletEVSE.FUNCTION_SET_STATUS_LED_CONFIG, (config,), 'B', 0, '')

    def get_status_led_config(self):
        """
        Returns the configuration as set by :func:`Set Status LED Config`
        """
        self.check_validity()

        return self.ipcon.send_request(self, BrickletEVSE.FUNCTION_GET_STATUS_LED_CONFIG, (), '', 9, 'B')

    def get_chip_temperature(self):
        """
        Returns the temperature as measured inside the microcontroller. The
        value returned is not the ambient temperature!

        The temperature is only proportional to the real temperature and it has bad
        accuracy. Practically it is only useful as an indicator for
        temperature changes.
        """
        self.check_validity()

        return self.ipcon.send_request(self, BrickletEVSE.FUNCTION_GET_CHIP_TEMPERATURE, (), '', 10, 'h')

    def reset(self):
        """
        Calling this function will reset the Bricklet. All configurations
        will be lost.

        After a reset you have to create new device objects,
        calling functions on the existing ones will result in
        undefined behavior!
        """
        self.check_validity()

        self.ipcon.send_request(self, BrickletEVSE.FUNCTION_RESET, (), '', 0, '')

    def write_uid(self, uid):
        """
        Writes a new UID into flash. If you want to set a new UID
        you have to decode the Base58 encoded UID string into an
        integer first.

        We recommend that you use Brick Viewer to change the UID.
        """
        self.check_validity()

        uid = int(uid)

        self.ipcon.send_request(self, BrickletEVSE.FUNCTION_WRITE_UID, (uid,), 'I', 0, '')

    def read_uid(self):
        """
        Returns the current UID as an integer. Encode as
        Base58 to get the usual string version.
        """
        self.check_validity()

        return self.ipcon.send_request(self, BrickletEVSE.FUNCTION_READ_UID, (), '', 12, 'I')

    def get_identity(self):
        """
        Returns the UID, the UID where the Bricklet is connected to,
        the position, the hardware and firmware version as well as the
        device identifier.

        The position can be 'a', 'b', 'c', 'd', 'e', 'f', 'g' or 'h' (Bricklet Port).
        A Bricklet connected to an :ref:`Isolator Bricklet <isolator_bricklet>` is always at
        position 'z'.

        The device identifier numbers can be found :ref:`here <device_identifier>`.
        |device_identifier_constant|
        """
        return GetIdentity(*self.ipcon.send_request(self, BrickletEVSE.FUNCTION_GET_IDENTITY, (), '', 33, '8s 8s c 3B 3B H'))

rnd = secrets.SystemRandom()

PORT = '/dev/ttyUSB0'

# use "with ChangedDirectory('/path/to/abc')" instead of "os.chdir('/path/to/abc')"
class ChangedDirectory:
    def __init__(self, path):
        self.path = path
        self.previous_path = None

    def __enter__(self):
        self.previous_path = os.getcwd()
        os.chdir(self.path)

    def __exit__(self, type_, value, traceback):
        os.chdir(self.previous_path)

@contextmanager
def temp_file():
    fd, name = tempfile.mkstemp()
    try:
        yield fd, name
    finally:
        try:
            os.remove(name)
        except IOError:
            print('Failed to clean up temp file {}'.format(name))

def run(args):
    return subprocess.check_output(args, env=dict(os.environ, LC_ALL="en_US.UTF-8")).decode("utf-8").split("\n")

def esptool(args):
    return run(["python3", "./esptool/esptool.py", *args])

def espefuse(args):
    return run(["python3", "./esptool/espefuse.py", *args])

colors = {"off":"\x1b[00m",
          "blue":   "\x1b[34m",
          "cyan":   "\x1b[36m",
          "green":  "\x1b[32m",
          "red":    "\x1b[31m",
          "gray": "\x1b[90m"}

def red(s):
    return colors["red"]+s+colors["off"]

def green(s):
    return colors["green"]+s+colors["off"]

def gray(s):
    return colors['gray']+s+colors["off"]

def remove_color_codes(s):
    for code in colors.values():
        s = s.replace(code, "")
    return s

def ansi_format(fmt, s):
    s = str(s)
    prefix = ""
    suffix = ""
    for code in colors.values():
        if s.startswith(code):
            s = s.replace(code, "")
            prefix += code
        if s.endswith(code):
            s = s.replace(code, "")
            suffix += code
    result = fmt.format(s)
    return prefix + result + suffix

def fatal_error(*args):
    for line in args:
        print(red(str(line)))
    sys.exit(0)

@contextmanager
def wifi(ssid, passphrase):
    output = "\n".join(run(["nmcli", "dev", "wifi", "connect", ssid, "password", passphrase]))
    if "successfully activated with" not in output:
        run(["nmcli", "con", "del", ssid])
        fatal_error("Failed to connect to wifi.", "nmcli output was:", output)

    try:
        yield
    finally:
        output = "\n".join(run(["nmcli", "con", "del", ssid]))
        if "successfully deleted." not in output:
            print("Failed to clean up wifi connection {}".format(ssid))


def get_new_uid():
    return int(urllib.request.urlopen('https://stagingwww.tinkerforge.com/uid', timeout=15).read())

def check_if_esp_is_sane_and_get_mac():
    output = esptool(['--port', PORT, 'flash_id']) # flash_id to get the flash size
    chip_type = None
    chip_revision = None
    flash_size = None
    crystal = None
    mac = None

    chip_type_re = re.compile(r'Chip is (ESP32-[^\s]*) \(revision (\d*)\)')
    flash_size_re = re.compile(r'Detected flash size: (\d*[KM]B)')
    crystal_re = re.compile(r'Crystal is (\d*MHz)')
    mac_re = re.compile(r'MAC: ((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})')

    for line in output:
        chip_type_match = chip_type_re.match(line)
        if chip_type_match:
            chip_type, chip_revision = chip_type_match.group(1, 2)

        flash_size_match = flash_size_re.match(line)
        if flash_size_match:
            flash_size = flash_size_match.group(1)

        crystal_match = crystal_re.match(line)
        if crystal_match:
            crystal = crystal_match.group(1)

        mac_match = mac_re.match(line)
        if mac_match:
            mac = mac_match.group(1)

    for name, val, expected in [("chip type", chip_type, "ESP32-D0WD-V3"), ("chip revision", chip_revision, "3"), ("crystal", crystal, "40MHz"), ("flash_size", flash_size, "16MB")]:
        if val != expected:
            fatal_error("{} was {}, not the expected {}".format(name, val, expected), "esptool output was:", '\n'.join(output))

    return mac

def get_esp_mac():
    esptool(['--port', PORT, 'read_mac'])

def get_espefuse_tasks():
    have_to_set_voltage_fuses = False
    have_to_set_block_3 = False

    output = espefuse(['--port', PORT, 'dump'])

    def parse_regs(line, regs):
        match = re.search(r'([0-9a-f]{8}\s?)' * regs, line)
        if not match:
            return False, []

        return True, [int(match.group(x + 1), base=16) for x in range(regs)]

    blocks = [None] * 4
    for line in output:
        if line.startswith('BLOCK0'):
            success, blocks[0] = parse_regs(line, 7)
        elif line.startswith('BLOCK1'):
            success, blocks[1] = parse_regs(line, 8)
        elif line.startswith('BLOCK2'):
            success, blocks[2] = parse_regs(line, 8)
        elif line.startswith('BLOCK3'):
            success, blocks[3] = parse_regs(line, 8)
        else:
            continue
        if not success:
            fatal_error("Failed to read eFuses", "could not parse line '{}'".format(line), "espefuse output was", '\n'.join(output))

    if any(b is None for b in blocks):
        fatal_error("Failed to read eFuses", "Not all blocks where found", "espefuse output was", '\n'.join(output))

    if any(i != 0 for i in blocks[1]):
        fatal_error("eFuse block 1 is not empty.", "espefuse output was", '\n'.join(output))

    if any(i != 0 for i in blocks[2]):
        fatal_error("eFuse block 1 is not empty.", "espefuse output was", '\n'.join(output))

    voltage_fuses = blocks[0][4] & 0x0001c000
    if voltage_fuses == 0x0001c000:
        have_to_set_voltage_fuses = False
    elif voltage_fuses == 0x00000000:
        have_to_set_voltage_fuses = True
    else:
        fatal_error("Flash voltage efuses have unexpected value {}".format(voltage_fuses), "espefuse output was", '\n'.join(output))

    block3_bytes = b''.join([r.to_bytes(4, "little") for r in blocks[3]])
    passphrase, uid = block3_to_payload(block3_bytes)

    if passphrase == '1-1-1-1' and uid == '1':
        have_to_set_block_3 = True
    else:
        passphrase_invalid = re.match('[{0}]{{4}}-[{0}]{{4}}-[{0}]{{4}}-[{0}]{{4}}'.format(BASE58), passphrase) is None
        uid_invalid = re.match('[{0}]{{3,6}}'.format(BASE58), uid) is None
        if passphrase_invalid or uid_invalid:
            fatal_error("Block 3 efuses have unexpected value {}".format(block3_bytes.hex()),
                        "parsed passphrase and uid are {}; {}".format(passphrase, uid),
                        "espefuse output was",
                        '\n'.join(output))

    return have_to_set_voltage_fuses, have_to_set_block_3, passphrase, uid

def payload_to_block3(passphrase, uid):
    passphrase_bytes_list = [base58decode(chunk).to_bytes(3, byteorder='little') for chunk in passphrase.split('-')]

    uid_bytes = base58decode(uid).to_bytes(4, byteorder='little')

    binary = bytearray(32)
    binary[7:10] = passphrase_bytes_list[0]
    binary[10:12] = passphrase_bytes_list[1][0:2]
    binary[20] = passphrase_bytes_list[1][2]
    binary[21:23] = passphrase_bytes_list[2][0:2]
    binary[24] = passphrase_bytes_list[2][2]
    binary[25:28] = passphrase_bytes_list[3]
    binary[28:32] = uid_bytes
    return binary

def block3_to_payload(block3):
    passphrase_bytes_list = [[0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0]]
    passphrase_bytes_list[0] = block3[7:10]
    passphrase_bytes_list[1][0:2] = block3[10:12]
    passphrase_bytes_list[1][2] = block3[20]
    passphrase_bytes_list[2][0:2] = block3[21:23]
    passphrase_bytes_list[2][2] = block3[24]
    passphrase_bytes_list[3] = block3[25:28]
    uid_bytes = bytes(block3[28:32])
    passphrase_bytes_list = [bytes(chunk) for chunk in passphrase_bytes_list]
    passphrase = [base58encode(int.from_bytes(chunk, "little")) for chunk in passphrase_bytes_list]
    uid = base58encode(int.from_bytes(uid_bytes, "little"))
    passphrase = '-'.join(passphrase)
    return passphrase, uid

def handle_voltage_fuses(set_voltage_fuses):
    if not set_voltage_fuses:
        print("Voltage fuses already burned.")
        return

    print("Burning flash voltage eFuse to 3.3V")
    espefuse(["--port", PORT, "set_flash_voltage", "3.3V", "--do-not-confirm"])

def handle_block3_fuses(set_block_3, uid, passphrase):
    if not set_block_3:
        print("Block 3 eFuses already set. UID: {}, Passphrase valid".format(uid))
        return uid, passphrase

    print("Reading staging password")
    try:
        with open('staging_password.txt', 'rb') as f:
            staging_password = f.read().decode('utf-8').split('\n')[0].strip()
    except:
        fatal_error('staging_password.txt missing or malformed')
        sys.exit(0)

    print("Installing auth_handler")
    if sys.version_info < (3,5,3):
        context = ssl.SSLContext(protocol=ssl.PROTOCOL_SSLv23)
    else:
        context = ssl.SSLContext()

    #context.verify_mode = ssl.CERT_REQUIRED
    #context.load_verify_locations(certifi.where())
    https_handler = urllib.request.HTTPSHandler(context=context)

    auth_handler = urllib.request.HTTPBasicAuthHandler()
    auth_handler.add_password(realm='Staging',
                                uri='https://stagingwww.tinkerforge.com',
                                user='staging',
                                passwd=staging_password)

    opener = urllib.request.build_opener(https_handler, auth_handler)
    urllib.request.install_opener(opener)

    print("Generating passphrase")
    # smallest 4-char-base58 string is "2111" = 195112 ("ZZZ"(= 195111) + 1)
    # largest 4-char-base58 string is "ZZZZ" = 11316495
    # Directly selecting chars out of the BASE58 alphabet can result in numbers with leading 1s
    # (those map to 0, so de- and reencoding will produce the same number without the leading 1)
    wifi_passphrase = [base58encode(rnd.randint(base58decode("2111"), base58decode("ZZZZ"))) for i in range(4)]
    print("Generating UID")
    uid = base58encode(get_new_uid())

    print("UID: " + uid)
    #print("Passphrase: {}-{}-{}-{}".format(*wifi_passphrase))

    print("Generating efuse binary")
    uid_bytes = base58decode(uid).to_bytes(4, byteorder='little')
    passphrase_bytes_list = [base58decode(chunk).to_bytes(3, byteorder='little') for chunk in wifi_passphrase]

    #56-95: 5 byte
    #160-183: 3 byte
    #192-255: 8 byte
    # = 16 byte

    # 4 byte (uid) + 3 byte * 4 (wifi_passphrase) = 16 byte
    binary = bytearray(32)
    binary[7:10] = passphrase_bytes_list[0]
    binary[10:12] = passphrase_bytes_list[1][0:2]
    binary[20] = passphrase_bytes_list[1][2]
    binary[21:23] = passphrase_bytes_list[2][0:2]
    binary[24] = passphrase_bytes_list[2][2]
    binary[25:28] = passphrase_bytes_list[3]
    binary[28:32] = uid_bytes

    with temp_file() as (fd, name):
        with os.fdopen(fd, 'wb') as f:
            f.write(binary)

        print("Burning UID and Wifi passphrase eFuses")
        espefuse(["--port", PORT, "burn_block_data", "BLOCK3", name, "--do-not-confirm"])

    return uid, '-'.join(wifi_passphrase)

def erase_flash():
    output = '\n'.join(esptool(["--port", PORT, "erase_flash"]))

    if "Chip erase completed successfully" not in output:
        fatal_error("Failed to erase flash.",
                    "esptool output was",
                    output)

def flash_firmware(path, reset=True):
    output = "\n".join(esptool(["--port", PORT,
                                    "--baud", "921600",
                                    "--before", "default_reset",
                                    "--after", "hard_reset" if reset else "no_reset",
                                    "write_flash",
                                    "--flash_mode", "dio",
                                    "--flash_freq", "40m",
                                    "--flash_size", "16MB",
                                    "0x1000", path]))

    if "Hash of data verified." not in output:
        fatal_error("Failed to flash firmware.",
                    "esptool output was",
                    output)

def wait_for_wifi(ssid, timeout_s):
    start = time.time()
    last_scan = 0
    while time.time() - start < timeout_s:
        if time.time() - last_scan > 15:
            try:
                run(["nmcli", "dev", "wifi", "rescan"])
            except:
                pass
            last_scan = time.time()
        output = '\n'.join(run(["nmcli", "dev", "wifi", "list"]))

        if ssid in output:
            return True
        time.sleep(1)
    return False

uids = set()

def cb_enumerate(uid, connected_uid, position, hardware_version, firmware_version,
                 device_identifier, enumeration_type):
    if enumeration_type == IPConnection.ENUMERATION_TYPE_DISCONNECTED:
        print("")
        return
    if device_identifier != 2127:
        return

    uids.add((position, uid))

def blink_thread_fn(rgbs, stop_event):
    while not stop_event.is_set():
        for rgb in rgbs:
            rgb.set_rgb_value(0,127,0)
            time.sleep(0.2)
        for rgb in rgbs:
            rgb.set_rgb_value(0,0,0)
            time.sleep(0.2)

def now():
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()


def my_input(s, color_fn=green):
    return input(color_fn(s) + " ")

def run_bricklet_tests(ipcon, result, qr_variant, qr_power):
    enumerations = []

    ipcon.register_callback(ipcon.CALLBACK_ENUMERATE, lambda *args: enumerations.append(args))
    ipcon.enumerate()
    time.sleep(3)

    master_uid = next((e for e in enumerations if e[5] == 13), [None])[0]
    evse_uid = next((e for e in enumerations if e[5] == 2159), [None])[0]
    rs485_uid = next((e for e in enumerations if e[5] == 277), [None])[0]

    is_basic = master_uid is not None
    is_pro = rs485_uid is not None
    is_smart = master_uid is None and rs485_uid is None

    if len(enumerations) not in [1, 2]:
        fatal_error("Unexpected number of devices! Expected 1 or 2 but got {}.".format(len(enumerations)))

    if evse_uid is None:
        fatal_error("No EVSE Bricklet found!")

    d = {"P": "Pro", "S": "Smart", "B": "Basic"}

    if is_basic and qr_variant != "B":
        fatal_error("Scanned QR code implies variant {}, but detected was Basic (i.e. an Master Brick was found)".format(d[qr_variant]))

    if is_smart and qr_variant != "S":
        fatal_error("Scanned QR code implies variant {}, but detected was Smart: An ESP32 Brick was found, not no RS485 Bricklet. Is the Bricklet not connected or the status LED not lighting up? Is the QR code correct?".format(d[qr_variant]))

    if is_pro and qr_variant != "P":
        fatal_error("Scanned QR code implies variant {}, but detected was Pro: An ESP32 Brick and a RS485 Bricklet was found. Is the QR code correct?".format(d[qr_variant]))

    result["evse_uid"] = evse_uid
    print("EVSE UID is {}".format(evse_uid))

    if is_basic:
        result["master_uid"] = master_uid
        print("Master UID is {}".format(master_uid))

    if is_pro:
        result["rs485_uid"] = rs485_uid
        print("RS485 UID is {}".format(rs485_uid))

    evse = BrickletEVSE(evse_uid, ipcon)
    jumper_config, has_lock_switch = evse.get_hardware_configuration()

    if qr_power == "11" and jumper_config != 3:
        fatal_error("Wrong jumper config detected: {} but expected {} as the configured power is {} kW.".format(jumper_config, 3, qr_power))

    if qr_power == "22" and jumper_config != 6:
        fatal_error("Wrong jumper config detected: {} but expected {} as the configured power is {} kW.".format(jumper_config, 6, qr_power))

    result["jumper_config_checked"] = True
    if has_lock_switch:
        fatal_error("Wallbox has lock switch. Is the diode missing?")

    result["diode_checked"] = True

    _configured, _incoming, outgoing, _managed = evse.get_max_charging_current()
    if qr_power == "11" and outgoing != 20000:
        fatal_error("Wrong type 2 cable config detected: Allowed current is {} but expected 20 A, as this is a 11 kW box.".format(outgoing / 1000))
    if qr_power == "22" and outgoing != 32000:
        fatal_error("Wrong type 2 cable config detected: Allowed current is {} but expected 32 A, as this is a 22 kW box.".format(outgoing / 1000))

    result["resistor_checked"] = True

    if is_pro:
        meter_str = urllib.request.urlopen('http://10.0.0.1/meter/live', timeout=3).read()
        print(meter_str)
        meter_data = json.loads(meter_str)
        sps = meter_data["samples_per_second"]
        samples = meter_data["samples"]
        if not 0.2 < sps < 2.5:
            fatal_error("Expected between 0.2 and 2.5 energy meter samples per second, but got {}".format(sps))
        if len(samples) < 2:
            fatal_error("Expected at least 10 samples but got {}".format(len(samples)))

        event_str = urllib.request.urlopen('http://10.0.0.1/event_log', timeout=3).read().decode('utf-8')
        if re.search(r"Request \d+: Exception code \d+", event_str):
            fatal_error("Found energy meter errors in event log:", event_str)

        if all(s == 0 for s in samples):
            fatal_error("Expected some samples not equal zero.", samples)

        result["energy_meter_reachable"] = True

def exists_evse_test_report(evse_uid):
    with open(os.path.join("evse_test_report", "full_test_log.csv"), newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        for row in reader:
            if row[0] == evse_uid:
                return True
    return False

def main():
    global uids

    result = {"start": now()}

    git_user = None
    if len(sys.argv) == 2:
        git_user = sys.argv[1]

    with urllib.request.urlopen("https://download.tinkerforge.com/latest_versions.txt") as f:
        latest_versions = f.read().decode("utf-8")

    match = re.search(r"bricklets:evse:(\d)\.(\d)\.(\d)", latest_versions)
    major = match.group(1)
    minor = match.group(2)
    patch = match.group(3)

    if not os.path.exists("firmwares"):
        os.mkdir("firmwares")

    evse_path = "bricklet_evse_firmware_{}_{}_{}.zbin".format(major, minor, patch)
    if not os.path.exists(evse_path):
        urllib.request.urlretrieve('https://download.tinkerforge.com/firmwares/bricklets/evse/{}'.format(evse_path), os.path.join("firmwares", evse_path))
    evse_path = os.path.join("firmwares", evse_path)

    #with urllib.request.urlopen("https://www.warp-charger.com/") as f:
    #    warp_charger_page = f.read().decode("utf-8")

    #match = re.search(r'<a href="firmwares/(warp_firmware_\d_\d_\d_[0-9a-f]{8}_merged.bin)" class="btn btn-primary btn-lg" id="download_latest_firmware">', #warp_charger_page)
    #firmware_path = match.group(1)

    #if not os.path.exists(firmware_path):
    #    urllib.request.urlretrieve('https://www.warp-charger.com/firmwares/{}'.format(firmware_path), os.path.join("firmwares", firmware_path))
    #firmware_path = os.path.join("firmwares", firmware_path)

    #T:WARP-CS-11KW-50-CEE;V:2.17;S:5000000001;B:2021-01;O:SO/B2020123;I:1/1;;
    pattern = r'^T:WARP-C(B|S|P)-(11|22)KW-(50|75)(|-CEE);V:(\d+\.\d+);S:(5\d{9});B:(\d{4}-\d{2});O:(SO/B?[0-9]+);I:(\d+/\d+)(?:;E:(\d+))?;;;*$'
    qr_code = my_input("Scan the docket QR code")
    match = re.match(pattern, qr_code)
    while not match:
        qr_code = my_input("Scan the docket QR code", red)
        match = re.match(pattern, qr_code)

    docket_variant = match.group(1)
    docket_power = match.group(2)
    docket_cable_len = match.group(3)
    docket_has_cee = match.group(4)
    docket_hw_version = match.group(5)
    docket_serial = match.group(6)
    docket_built = match.group(7)
    docket_order = match.group(8)
    docket_item = match.group(9)
    docket_supply_cable_extension = match.group(10)

    if docket_supply_cable_extension is None:
        docket_supply_cable_extension = 0
    else:
        docket_supply_cable_extension = int(docket_supply_cable_extension)

    print("Docket QR code data:")
    print("    WARP Charger {}".format({"B": "Basic", "S": "Smart", "P": "Pro"}[docket_variant]))
    print("    {} kW".format(docket_power))
    print("    {:1.1f} m".format(int(docket_cable_len) / 10.0))
    print("    CEE: {}".format("Yes" if docket_has_cee == "-CEE" else "No"))
    print("    HW Version: {}".format(docket_hw_version))
    print("    Serial: {}".format(docket_serial))
    print("    Build month: {}".format(docket_built))
    print("    Order: {}".format(docket_order))
    print("    Item: {}".format(docket_item))
    print("    Supply Cable Extension: {}".format(docket_supply_cable_extension))

    result["order"] = docket_order
    result["order_item"] = docket_item
    result["supply_cable_extension"] = docket_supply_cable_extension
    result["docket_qr_code"] = match.group(0)

    #T:WARP-CS-11KW-50-CEE;V:2.17;S:5000000001;B:2021-01;;
    pattern = r'^T:WARP-C(B|S|P)-(11|22)KW-(50|75)(|-CEE);V:(\d+\.\d+);S:(5\d{9});B:(\d{4}-\d{2});;;*$'
    qr_code = my_input("Scan the wallbox QR code")
    match = re.match(pattern, qr_code)
    while not match:
        qr_code = my_input("Scan the wallbox QR code", red)
        match = re.match(pattern, qr_code)

    qr_variant = match.group(1)
    qr_power = match.group(2)
    qr_cable_len = match.group(3)
    qr_has_cee = match.group(4)
    qr_hw_version = match.group(5)
    qr_serial = match.group(6)
    qr_built = match.group(7)

    if docket_variant != qr_variant or \
       docket_power != qr_power or \
       docket_cable_len != qr_cable_len or \
       docket_has_cee != qr_has_cee or \
       docket_hw_version != qr_hw_version or \
       docket_serial != qr_serial or \
       docket_built != qr_built:
        fatal_error("Docket and wallbox QR code do not match!")

    print("Wallbox QR code data:")
    print("    WARP Charger {}".format({"B": "Basic", "S": "Smart", "P": "Pro"}[qr_variant]))
    print("    {} kW".format(qr_power))
    print("    {:1.1f} m".format(int(qr_cable_len) / 10.0))
    print("    CEE: {}".format("Yes" if qr_has_cee == "-CEE" else "No"))
    print("    HW Version: {}".format(qr_hw_version))
    print("    Serial: {}".format(qr_serial))
    print("    Build month: {}".format(qr_built))

    result["serial"] = qr_serial
    result["qr_code"] = match.group(0)

    if qr_variant != "B":
        pattern = r"^WIFI:S:(esp32|warp)-([{BASE58}]{{3,6}});T:WPA;P:([{BASE58}]{{4}}-[{BASE58}]{{4}}-[{BASE58}]{{4}}-[{BASE58}]{{4}});;$".format(BASE58=BASE58)
        qr_code = getpass.getpass(green("Scan the ESP Brick QR code"))
        match = re.match(pattern, qr_code)
        while not match:
            qr_code = getpass.getpass(red("Scan the ESP Brick QR code"))
            match = re.match(pattern, qr_code)

        hardware_type = match.group(1)
        esp_uid_qr = match.group(2)
        passphrase_qr = match.group(3)

        print("ESP Brick QR code data:")
        print("    Hardware type: {}".format(hardware_type))
        print("    UID: {}".format(esp_uid_qr))

        if not os.path.exists(PORT):
            fatal_error("/dev/ttyUSB0 does not exist. Is the USB cable plugged in?")

        set_voltage_fuses, set_block_3, passphrase, uid = get_espefuse_tasks()
        output = esptool(['--port', PORT, '--after', 'hard_reset', 'flash_id'])
        if set_voltage_fuses:
            fatal_error("Voltage fuses not set!")

        if set_block_3:
            fatal_error("Block 3 fuses not set!")

        if esp_uid_qr != uid:
            fatal_error("ESP UID written in fuses ({}) does not match the one on the QR code ({})".format(uid, esp_uid_qr))

        if passphrase_qr != passphrase:
            fatal_error("Wifi passphrase written in fuses does not match the one on the QR code")

        result["uid"] = uid

        run(["systemctl", "restart", "NetworkManager.service"])

        ssid = "warp-" + uid

        print("Waiting for ESP wifi. Takes about one minute.")
        if not wait_for_wifi(ssid, 120):
            fatal_error("ESP wifi not found after 120 seconds")

        with wifi(ssid, passphrase):
            try:
                with urllib.request.urlopen("http://10.0.0.1/hidden_proxy/enable") as f:
                    f.read()
            except Exception as e:
                print("Failed to enable hidden proxy. Flashing new firmware.")
                print(e)
                print("Erasing flash")
                erase_flash()

                print("Flashing firmware")
                flash_firmware(os.path.join('..','..','..', 'warp_firmware_1_2_3_60cb5c5b_merged.bin'))

                result["firmware"] = "warp_firmware_1_2_3_60cb5c5b_merged.bin"

                run(["systemctl", "restart", "NetworkManager.service"])
                print("Waiting for ESP wifi. Takes about one minute.")
                if not wait_for_wifi(ssid, 120):
                    fatal_error("ESP wifi not found after 120 seconds")

                output = "\n".join(run(["nmcli", "dev", "wifi", "connect", ssid, "password", passphrase]))
                if "successfully activated with" not in output:
                    run(["nmcli", "con", "del", ssid])
                    fatal_error("Failed to connect to wifi.", "nmcli output was:", output)

                with urllib.request.urlopen("http://10.0.0.1/hidden_proxy/enable") as f:
                    f.read()

            ipcon = IPConnection()
            try:
                ipcon.connect("10.0.0.1", 4223)
            except Exception as e:
                fatal_error("Failed to connect to ESP proxy")

            run_bricklet_tests(ipcon, result, qr_variant, qr_power)
    else:
        result["uid"] = None
        ipcon = IPConnection()
        ipcon.connect("localhost", 4223)
        run_bricklet_tests(ipcon, result, qr_variant, qr_power)
        print("Flashing EVSE")
        run(["python3", "comcu_flasher.py", result["evse_uid"], evse_path])
        result["evse_firmware"] = evse_path

    print("Checking if EVSE was tested...")
    if not exists_evse_test_report(result["evse_uid"]):
        if git_user is None:
            fatal_error("No test report found for EVSE {} and git username is unknown. Please pull the wallbox git.".format(result["evse_uid"]))
        print("No test report found. Checking for new test reports...")
        with ChangedDirectory(os.path.join("..", "..", "wallbox")):
            run(["su", git_user, "-c", "git pull"])
        if not exists_evse_test_report(result["evse_uid"]):
            fatal_error("No test report found for EVSE {}.".format(result["evse_uid"]))

    print("EVSE test report found")
    result["evse_test_report_found"] = True

    if qr_variant == "B":
        ssid = "warp-" + result["evse_uid"]

    result["end"] = now()

    with open("{}_{}_report_stage_2.json".format(ssid, now().replace(":", "-")), "w") as f:
        json.dump(result, f, indent=4)

    if qr_variant != "B":
        with wifi(ssid, passphrase):
            my_input("Pull the USB cable, do the electrical tests and press any key when done")

        # Restart NetworkManager to reconnect to the "default" wifi
        run(["systemctl", "restart", "NetworkManager.service"])

    print('Done!')

if __name__ == "__main__":
    main()
