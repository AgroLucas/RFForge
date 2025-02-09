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

from devices.TX.tx import Tx
from devices.keyboard import * 

class Tx_Keyboard(Tx):
    """Represents a TX keyboard.
    
    Successfully tested with the ms6-TXn-wH mouse.
    """

    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))


    def parse_packet(self, packet):
        p = packet[:self.packet_size]

        sequence_int = int.from_bytes(p[4:5], "big")
        sequence_number = hex((((sequence_int >> 2) & 1) << 1) | ((sequence_int >> 1) & 1)) # get 3rd and 2nd bits
        status_int = int.from_bytes(p[5:6], "big")
        status = hex((((status_int >> 2) & 1) << 1) | ((status_int >> 1) & 1))
        return {
            "address"           : p[:self.address_length].hex(),
            "payload"           : p[:-self.crc_size].hex(),
            "sequence_number"   : sequence_number,
            "status_number"     : status,
            "flags"             : p[6:7].hex(),
            "array"             : p[7:12].hex(),
            "crc"               : p[-self.crc_size:].hex()
            }


    def build_packet(self, scancodes=[], modifiers=[]):
        """Build 2 raw packets. One key on, one key off.

        Args: 
            scancodes (list[KeyboardScancode]): A list of KeyboardScancode to include in the first packet.
            modifiers (list[KeyboardModifiers]): A list of KeyboardModifiers to include in the first packet.

        Returns:
            bytes: A table containing 2 raw packet in bytes format, the second one is an empty packet to simulate a key release (they does not contain the preamble).
        """
        packets = []
        address = unhexlify(self.address.replace(':', ''))

        for i in range (2): # send key down and key up
            status_byte = b"\x03"
            padding = b"\x00\x01"
            if i == 0:
                flags = self.build_flags(modifiers)
                array = self.build_array(scancodes)
                sequence_number_byte = b"\x49"
            else:
                flags = b"\x00"
                array = b"\x00\x00\x00\x00\x00"
                sequence_number_byte = b"\x4B"
            crc = self.calculate_crc(address+sequence_number_byte+status_byte+flags+array+padding)
            packets.append(address+sequence_number_byte+status_byte+flags+array+padding+crc)
        return packets
    
    
    def build_array(self, scancodes):
        """Build the array based on the scancodes given.

        An array is a certain number of bytes (often 6) specified by USB HID that represents the pressed characters of a keyboard.

        Args: 
            scancodes (list[KeyboardScancode]): A list of KeyboardScancode to include in the array.       
        
        Returns:
            bytes: The raw array of a packet including exactly 5 scancodes in bytes format.
        """
        array = b""
        for i in range(len(scancodes)):
            if i == 6 :
                break
            if scancodes[i] in KeyboardScancode:
                array += scancodes[i].value.to_bytes(1, "big")
        array += unhexlify("00" * (5 - len(scancodes)))
        return array


    def build_flags(self, modifiers):
        """Build the flag byte based on the modifiers given.

        Args: 
            modifiers (list[KeyboardModifiers]): A list of KeyboardModifiers to include in the byte.
        
        Returns:
            bytes: A 1 byte value containing the given modifiers.
        """
        flags = 0
        for modifier in modifiers:
            if modifier in KeyboardModifiers:
                flags |= modifier.value
        return flags.to_bytes(1, "big")
    

    def handle_sniffed_packet(self, packet, channel):
        if self.check_crc(packet["crc"], packet["payload"]):
            print(f"TX Keyboard Packet\tCHANNEL : {channel}")
            print(packet)
            print(self.scancode_to_char(packet["array"]))
