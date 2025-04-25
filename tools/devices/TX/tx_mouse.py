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

import crcmod
from binascii import unhexlify

from devices.TX.tx import Tx
from devices.mouse import *

class Tx_mouse(Tx):
    """Represents a TX mouse.
    
    Successfully tested with the ms6-TXn-wh.
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
            "click_type"        : p[6:7].hex(),
            "scrolling"         : p[7:8].hex(),
            "x"                 : p[8:10].hex(),
            "y"                 : p[10:12].hex(),
            "crc"               : p[-self.crc_size:].hex()
            }


    def build_packet(self, clicks, x_move="0000", y_move="0000", scrolling_move="00"):
        """Build 2 raw packets. One key on, one key off.

        Args: 
            clicks (list[MouseClickType]): A list of MouseClickType to include in the first packet.
            x_move (str): The movement of the mouse in the x axis in hexadecimal string.
            y_move (str): The movement of the mouse in the y axis in hexadecimal string.
            scrolling_move (str): The movement of the wheel in signed hexadecimal string.

        Returns:
            list[bytes]: A table containing 2 raw packet in bytes format, the second one is an empty packet to simulate a click release.
        """
        packets = []
        address = unhexlify(self.address.replace(':', ''))

        for i in range(2):
            padding = b"\x33\xF1"
            if i == 0:
                status_byte = b"\x02"
                sequence_number_byte = b"\x49"
                x = unhexlify(x_move)
                y = unhexlify(y_move)
                click_type = self.build_clicks(clicks)
                scrolling = unhexlify(scrolling_move)
            else:
                status_byte = b"\x04"
                sequence_number_byte = b"\x4B"
                x = b"\x00\x00"
                y = b"\x00\x00"
                click_type = b"\x00"
                scrolling = b"\x00"
            crc = self.calculate_crc(address+sequence_number_byte+status_byte+click_type+scrolling+x+y+padding)
            packets.append(address+sequence_number_byte+status_byte+click_type+scrolling+x+y+padding+crc)
        return packets
    

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
            print(f"TX Mouse Packet\tCHANNEL : {channel}")
            print(packet)
            return True
        return False
    