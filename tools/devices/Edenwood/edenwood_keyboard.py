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

from devices.Edenwood.edenwood import Edenwood
from devices.keyboard import * 


class Edenwood_Keyboard(Edenwood):
    """ Represents an Edenwood keyboard.
    
    Successfully tested with the 963716 CWL01 keyboard.
    """

    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 0
        self.sniffed_keys = ""


    def parse_packet(self, packet):
        p = packet[:self.packet_size]
        sequence_int = int.from_bytes(p[5:6], "big")
        sequence_number = hex((((sequence_int >> 2) & 1) << 1) | ((sequence_int >> 1) & 1)) # get 3rd and 2nd bits
        modifiers = int.from_bytes(p[6:7], "big")
        return {"address" :         p[:self.address_length].hex(),
                "payload" :         p[:-self.crc_size].hex(),
                "sequence number":  sequence_number,
                "array":            [hex(item) for item in p[7:13]],
                "checksum":         p[16:17].hex(),
                "crc" :             p[-self.crc_size:].hex(),
                "raw modifiers":    modifiers,
                "modifiers" : {
                    "is left ctrl" :            (modifiers >> 0) & 1,
                    "is left shift" :           (modifiers >> 1) & 1,
                    "is left alt" :             (modifiers >> 2) & 1,
                    "is left gui" :             (modifiers >> 3) & 1,
                    "is right ctrl" :           (modifiers >> 4) & 1,
                    "is right shift" :          (modifiers >> 5) & 1,
                    "is right alt" :            (modifiers >> 6) & 1
                    }
                }
    

    def scancodes_to_string(self, array, modifiers):
        """Convert an list of scancodes and modifiers into a string.

        Args:
            array (list[str]): A list containing USB HID scancode in hexadecimal string.
            modifiers (bytes): A byte containing the modifiers' flags.
        
        Returns:
            str: A string containing the characters from the array by taking into account the modifiers.
        """
        is_shift = ((modifiers >> 1) & 1) or ((modifiers >> 5) & 1)
        is_altgr = (modifiers >> 6) & 1
        modifier = int(is_shift) + (2 * int(is_altgr))
        chars = ""
        for scancode in array:
            chars += KeyboardScancode.SCANCODE_TO_CHAR.value.get((int(scancode, 16), modifier), "")
        return chars


    def build_packet(self, scancodes=[], modifiers=[]):
        """Build a raw packet based on the scancodes given.

        Args: 
            scancodes (list[KeyboardScancode]): A list of KeyboardScancode to include in the packet.

        Returns:
            bytes: A raw packet in bytes format (it does not contain the preamble).
        """
        address = unhexlify(self.address.replace(':', ''))
        sequence_number = (0x59 | (self.sequence_number << 1)).to_bytes(1, "big") # sequence number is in 2nd and 3rd bits
        self.sequence_number = (self.sequence_number + 1) % 4 # update object's sequence number
        flags = self.build_flags(modifiers)
        array = self.build_array(scancodes)
        padding = b"\x00\x00\x00"
        checksum = self.calculate_checksum(int.from_bytes(flags, "big"), [int(x) for x in array])
        crc = self.calculate_crc(address+sequence_number+flags+array+padding+checksum)
        
        return address+sequence_number+flags+array+padding+checksum+crc
    

    def build_flags(self, modifiers):
        """Build the flag byte based on the modifiers given.

        Args: 
            modifiers (list[KeyboardModifiers]): A list of KeyboardModifiers to include in the byte.
        
        Returns:
            bytes: A 2 bytes value containing the given modifiers.
        """
        flags = 0
        for modifier in modifiers:
            if modifier in KeyboardModifiers:
                flags |= modifier.value
        return flags.to_bytes(1, "big")
    

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
    

    def calculate_checksum(self, modifiers, array):
        """Calculate the checksum for the Edenwood keyboard.

        Args:
            modifiers (int): The modifiers value.
            array (list[int]): The list of pressed keys.

        Returns:
            bytes: The checksum for the Edenwood keyboard in byte.
        """
        return  ((modifiers + sum(array)) % 256).to_bytes(1, "big")
    

    def handle_sniffed_packet(self, packet, channel):
        if self.check_crc(packet["crc"], packet["payload"]):
            print(f"Edenwood Keyboard Packet\tCHANNEL : {channel}")
            print(packet)
            self.sniffed_keys += self.scancodes_to_string(packet["array"], packet["raw modifiers"])
            print(self.sniffed_keys)
            return True
        return False
    