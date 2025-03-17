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
from devices.mouse import *

class Edenwood_Mouse(Edenwood):
    """Represents an Edenwood mouse.
    
    Successfully tested with the 963716 CWL01 mouse.
    """
    
    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 0


    def parse_packet(self, packet):
        p = packet[:self.packet_size]
        sequence_int = int.from_bytes(p[5:6], "big")
        sequence_number = hex((((sequence_int >> 2) & 1) << 1) | ((sequence_int >> 1) & 1)) # get 3rd and 2nd bits
        return {"address" :         p[:self.address_length].hex(),
                "payload" :         p[:-self.crc_size].hex(),
                "sequence number":  sequence_number,
                "click type":       p[6:7].hex(),
                "x":                p[7:9].hex(),
                "y":                p[9:11].hex(),
                "scrolling":        p[11:12].hex(),
                "checksum":         p[16:17].hex(),
                "crc" :             p[-self.crc_size:].hex()
                }


    def build_packet(self, clicks, x_move="0000", y_move="0000", scrolling_move="00"):
        """Build a raw packet.

        Args: 
            clicks (list[MouseClickType]): A list of MouseClickType to include in the packet.
            x_move (str): The movement of the mouse in the x axis in hexadecimal string.
            y_move (str): The movement of the mouse in the y axis in hexadecimal string.
            scrolling_move (str): The movement of the wheel in signed hexadecimal string.

        Returns:
            bytes: A raw packet in bytes format (it does not contain the preamble).
        """
        address = unhexlify(self.address.replace(':', ''))
        sequence_number = (0x59 | (self.sequence_number << 1)).to_bytes(1, "big") # sequence number is in 2nd and 3rd bits
        self.sequence_number = (self.sequence_number + 1) % 4 # update object's sequence number
        click_type = self.build_clicks(clicks)
        x = unhexlify(x_move)
        y = unhexlify(y_move)
        scrolling = unhexlify(scrolling_move)
        padding = b"\x00\x00\x00\x00"
        checksum = self.calculate_checksum(int.from_bytes(click_type, "big"), int.from_bytes(x, "big"), int.from_bytes(y, "big"), int.from_bytes(scrolling, "big"))
        crc = self.calculate_crc(address+sequence_number+click_type+x+y+scrolling+padding+checksum)

        return address+sequence_number+click_type+x+y+scrolling+padding+checksum+crc
    

    def build_clicks(self, clicks):
        """Build the click byte based on the clicks given.

        Args: 
            clicks (list[MouseClickType]): A list containing the pressed clicks.       
        
        Returns:
            bytes: The byte containing the correct value based on the pressed clicks.
        """
        click_result = 0
        for click in clicks:
            if click in MouseClickType:
                click_result |= click.value
        return click_result.to_bytes(1, "big")
    

    def calculate_checksum(self, click_type, x, y, scrolling):
        """Calculate the checksum for the Edenwood mouse.

        Args:
            click_type (int): The click value.
            x (int): The x value.
            y (int): The y value.
            scrolling (int): The scrolling value.

        Returns:
            bytes: The checksum for the Edenwood mouse in byte.
        """
        offset = 0
        if scrolling > 255:
            offset += 1
        if x > 255:
            offset += 1
        if y > 255:
            offset += 1
        return  ((click_type + x + y + scrolling - offset) % 256).to_bytes(1, "big")
        

    def handle_sniffed_packet(self, packet, channel):
        if self.check_crc(packet["crc"], packet["payload"]):
            print(f"Edenwood Mouse Packet\tCHANNEL : {channel}")
            print(packet)
            return True
        return False
