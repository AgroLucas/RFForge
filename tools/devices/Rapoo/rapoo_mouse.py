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
from devices.mouse import *

class Rapoo_Mouse(Rapoo):
    """Represents a Rapoo mouse.
    
    Successfully tested with the M10 mouse.
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
                "click" :           p[13:14].hex(),
                "x" :               p[14:16].hex(),
                "y" :               p[16:18].hex(),
                "scrolling":        p[18:19].hex(),
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
        beginning_payload = b"\xdc\x69\x04"
        sequence_number = self.sequence_number.to_bytes(1, "big")
        self.sequence_number = (self.sequence_number + 1) % 255
        padding = b"\x01\x01\x4c\xa2\x2e"
        click_type = self.build_clicks(clicks)
        x = unhexlify(x_move)
        y = unhexlify(y_move)
        scrolling = unhexlify(scrolling_move)
        crc = self.calculate_crc(address+beginning_payload+sequence_number+padding+click_type+x+y+scrolling)

        return address+beginning_payload+sequence_number+padding+click_type+x+y+scrolling+crc
    

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
    

    def handle_sniffed_packet(self, packet, channel):
        if self.check_crc(packet["crc"], packet["payload"]):
            if packet["packet type"] == "04":
                print(f"Rapoo Mouse Packet\tCHANNEL : {channel}")
                print(packet)
                return True
        return False
