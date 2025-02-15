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

from lib import common
from devices.device import Device
from devices.keyboard import * 

class Qware_Keyboard(Device):
    """Represents a Qware Keyboard.
    
    Successfully tested with the QW PCB-238BL keyboard.
    """
    ADDRESS_LENGTH = 4
    CHANNELS = [2, 14, 18, 22, 30, 38, 50, 62, 66, 68, 70, 78]
    RATE = common.RF_RATE_2M
    PACKET_SIZE = 18
    PREAMBLE = "AA:AA"
    CRC_SIZE = 2



    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, self.ADDRESS_LENGTH, self.CHANNELS, self.RATE, self.PACKET_SIZE, self.PREAMBLE, self.CRC_SIZE, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 0


    def parse_packet(self, packet):
        p = packet[:self.packet_size]

        sequence_int = int.from_bytes(p[7:8], "big")
        sequence_number = hex((((sequence_int >> 2) & 1) << 1) | ((sequence_int >> 1) & 1)) # get 3rd and 2nd bits

        mask_array = 0x3b0d6d2af9bc
        xored_array = int.from_bytes(p[10:16], byteorder="big")
        unxored_array = xored_array ^ mask_array

        mask_modifiers = 0xF5
        xored_modifiers = int.from_bytes(p[9:10], "big")
        unxored_modifiers = xored_modifiers ^ mask_modifiers
        return {
            "address" :             p[:self.address_length].hex(),
            "payload" :             p[:-self.crc_size].hex(),
            "sequence number":      sequence_number,
            "array":                [hex(byte) for byte in unxored_array.to_bytes(6, byteorder="big")],
            "crc" :                 p[-self.crc_size:].hex(),
                "raw modifiers":    unxored_modifiers,
                "modifiers" : {
                    "is left ctrl" :            (unxored_modifiers >> 0) & 1,
                    "is left shift" :           (unxored_modifiers >> 1) & 1,
                    "is left alt" :             (unxored_modifiers >> 2) & 1,
                    "is left gui" :             (unxored_modifiers >> 3) & 1,
                    "is right ctrl" :           (unxored_modifiers >> 4) & 1,
                    "is right shift" :          (unxored_modifiers >> 5) & 1,
                    "is right alt" :            (unxored_modifiers >> 6) & 1
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
        beginning_payload = b"\x12\x12\x12"
        sequence_number = (0x40 | (self.sequence_number << 1)).to_bytes(1, "big") # sequence number is in 2nd and 3rd bits starting from right
        self.sequence_number = (self.sequence_number + 1) % 4
        padding = b"\x00"
        flags = self.build_flags(modifiers)
        array = self.build_array(scancodes)
        crc = self.calculate_crc(address+beginning_payload+sequence_number+padding+flags+array)

        return address+beginning_payload+sequence_number+padding+flags+array+crc
    

    def build_flags(self, modifiers):
        """Build the flag byte based on the modifiers given.

        Args: 
            modifiers (list[KeyboardModifiers]): A list of KeyboardModifiers to include in the byte.
        
        Returns:
            bytes: A 2 bytes value containing the given modifiers xored with the appropriate mask for qware.
        """
        mask_modifiers = 0xF5
        flags = 0
        for modifier in modifiers:
            if modifier in KeyboardModifiers:
                flags |= modifier.value
        return (flags ^ mask_modifiers).to_bytes(1, "big")
    

    def build_array(self, scancodes):
        """Build the array based on the scancodes given.

        An array is a certain number of bytes (often 6) specified by USB HID that represents the pressed characters of a keyboard.

        Args: 
            scancodes (list[KeyboardScancode]): A list of KeyboardScancode to include in the array.       
        
        Returns:
            bytes: The raw array of a packet including exactly 6 scancodes in bytes format and xored using the appropriate mask for qware.
        """
        mask_array = 0x3b0d6d2af9bc
        array = b""
        for i in range(len(scancodes)):
            if i == 6 :
                break
            if scancodes[i] in KeyboardScancode:
                array += scancodes[i].value.to_bytes(1, "big")
        array += unhexlify("00" * (6 - len(scancodes)))
        return bytes(a ^ b for a, b in zip(array, mask_array.to_bytes(6, "big")))

    

    def handle_sniffed_packet(self, packet, channel):
        if self.check_crc(packet["crc"], packet["payload"]):
            print(f"Qware Keyboard Packet\tCHANNEL : {channel}")
            print(packet)
            print(self.scancodes_to_string(packet["array"], packet["raw modifiers"]))
            return True
        return False
