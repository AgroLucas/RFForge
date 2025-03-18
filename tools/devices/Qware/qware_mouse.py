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

from devices.mouse import *
from devices.Qware.qware import Qware

class Qware_Mouse(Qware):
    """Represents a Qware mouse.
    
    Successfully tested with the QW PCB-238BL mouse.
    """

    PACKET_SIZE = 23

    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, self.PACKET_SIZE, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 0


    def parse_packet(self, packet):
        p = packet[:self.packet_size]

        sequence_int = int.from_bytes(p[7:8], "big")
        sequence_number = hex((((sequence_int >> 2) & 1) << 1) | ((sequence_int >> 1) & 1)) # get 3rd and 2nd bits

        mask_click = 0xF5
        xored_click = int.from_bytes(p[9:10], "big")
        unxored_click = xored_click ^ mask_click

        mask_scrolling = 0xBC
        xored_scrolling = int.from_bytes(p[15:16], "big")
        unxored_scrolling = xored_scrolling ^ mask_scrolling


        mask_x = 0x3B0D6D2AF9
        mask_y = 0x518E4CFDC1
        xored_x = int.from_bytes(p[10:15], "big")
        xored_y = int.from_bytes(p[16:21], "big")
        unxored_x = xored_x ^ mask_x
        unxored_y = xored_y ^ mask_y
        

        return {"address" :         p[:self.address_length].hex(),
                "payload" :         p[:-self.crc_size].hex(),
                "sequence number":  sequence_number,
                "click type" :      unxored_click.to_bytes(1, byteorder="big").hex(),
                "scrolling":        unxored_scrolling.to_bytes(1, byteorder="big").hex(),
                "x" :               unxored_x.to_bytes(5, byteorder="big").hex(),
                "y" :               unxored_y.to_bytes(5, byteorder="big").hex(),
                "crc" :             p[-self.crc_size:].hex()
                }


    def build_packet(self, clicks, x_move="00000", y_move="00000", scrolling_move="00"):
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
        padding = b"\xee\x10"
        sequence_number = (0x68 | (self.sequence_number << 1)).to_bytes(1, "big") # sequence number is in 2nd and 3rd bits starting from right
        self.sequence_number = (self.sequence_number + 1) % 4
        padding2 = b"\x10"
        click_type = self.build_clicks(clicks)
        x = (int(x_move, 16) ^ 0x3B0D6D2AF9).to_bytes(5, byteorder="big")
        y = (int(y_move, 16) ^ 0x518E4CFDC1).to_bytes(5, byteorder="big")
        scrolling = (int(scrolling_move, 16) ^ 0xbc).to_bytes(1, byteorder="big")
        crc = self.calculate_crc(address+padding+sequence_number+padding2+click_type+x+scrolling+y)

        return address+padding+sequence_number+padding2+click_type+x+scrolling+y+crc
    

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
        return (click_result ^ 0xF5).to_bytes(1, "big")
        

    def handle_sniffed_packet(self, packet, channel):
        if self.check_crc(packet["crc"], packet["payload"]):
            print(f"Qware Mouse Packet\tCHANNEL : {channel}")
            print(packet)
            return True
        return False
