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

import crcmod
from binascii import unhexlify

from devices.Rapoo.rapoo import Rapoo
from devices.keyboard import * 


class Rapoo_Keyboard(Rapoo):
    """ Represents a Rapoo keyboard.
    
    Successfully tested with the E1050 keyboard.
    """

    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 0


    def parse_packet(self, packet):
        p = packet[:self.packet_size]
        return {"address" :         p[:self.address_length].hex(),
                "payload" :         p[:-self.crc_size].hex(),
                "packet type" :     p[6:7].hex(),
                "sequence number":  p[7:8].hex(),
                "array":            [hex(item) for item in p[-(6+self.crc_size):-self.crc_size]],
                "crc" :             p[-self.crc_size:].hex()
                }
    

    def scancodes_to_string(self, array):
        """Convert an list of scancodes into a string.

        Also handles the modifiers (l/r shift and r alt)

        Args:
            array (list[str]): A list containing USB HID scancode in hexadecimal string.
        
        Returns:
            str: A string containing the characters from the list.
        """
        modifiers = 0
        shifted = False
        for scancode in array: # grab potential modifiers
            value = int(scancode, 16)
            if value == KeyboardScancode.KEY_LSHIFT.value or value == KeyboardScancode.KEY_RSHIFT.value and not shifted:
                modifiers += 1
                shifted = True # avoid incrementing modifier 2 times in case we press L and R shift at the same time
            elif value == KeyboardScancode .KEY_RALT.value:
                modifiers += 2
        chars = ""
        for scancode in array:
            chars += KeyboardScancode.SCANCODE_TO_CHAR.value.get((int(scancode, 16), modifiers), "")
        return chars


    def build_packet(self, scancodes=[]):
        """Build a raw packet based on the scancodes given.

        Args: 
            scancodes (list[KeyboardScancode]): A list of KeyboardScancode to include in the packet.

        Returns:
            bytes: A raw packet in bytes format (it does not contain the preamble).
        """
        address = unhexlify(self.address.replace(':', ''))
        sequence_number = self.sequence_number.to_bytes(1, "big")
        self.sequence_number = (self.sequence_number + 1) % 255
        padding = b"\x01\x02\xea\x3a\x16"
        array = self.build_array(scancodes)
        crc = self.calculate_crc(address+sequence_number+padding+array)
        
        return address+sequence_number+padding+array+crc
    

    def build_array(self, scancodes):
        """Build the array based on the scancodes given.

        An array is a certain number of bytes (often 6) specified by USB HID that represents the pressed characters of a keyboard.

        Args: 
            scancodes (list[KeyboardScancode]): A list of KeyboardScancode to include in the array.       
        
        Returns:
            bytes: The raw array of a packet including exactly 6 scancodes in bytes format.
        """
        array = b""
        for i in range(len(scancodes)):
            if i == 6 :
                break
            if scancodes[i] in KeyboardScancode:
                array += scancodes[i].value.to_bytes(1, "big")
        array += unhexlify("00" * (6 - len(scancodes)))
        return array
    

    def handle_sniffed_packet(self, packet, channel):
        if self.check_crc(packet["crc"], packet["payload"]):
            if packet["packet type"] == "06":
                print(f"Rapoo Keyboard Packet\tCHANNEL : {channel}")
                print(packet)
                print(self.scancodes_to_string(packet["array"]))
                return True
        return False

    