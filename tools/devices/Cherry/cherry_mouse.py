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
from devices.mouse import *

class Cherry_Mouse(Device):
    """Represents a Cherry mouse.

    """
    ADDRESS_LENGTH = 4
    CHANNELS = [20, 46, 72]
    RATE = common.RF_RATE_1M
    PACKET_SIZE_1 = 16
    PACKET_SIZE_2 = 19
    PREAMBLE = "8A"
    CRC_SIZE = 2


    # TODO change device.py to include multiple packet size and crcs
    # TODO implement parsing of packet and spoofing
    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, self.ADDRESS_LENGTH, self.CHANNELS, self.RATE, self.PACKET_SIZE_1, self.PREAMBLE, self.CRC_SIZE, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 0
        self.crcs = [crcmod.mkCrcFun(0x11021, initCrc=0x3c32, rev=False, xorOut=0x0000),
                crcmod.mkCrcFun(0x11021, initCrc=0xd791, rev=False, xorOut=0x0000)]

    
    def check_crc(self, expected_crc, crc_input):
        for crc in self.crcs:
            if f"{crc(unhexlify(crc_input)):04x}" == expected_crc:
                return True
        return False


    def parse_packet(self, packet):
        p1 = packet[:self.PACKET_SIZE_1]
        p2 = packet[:self.PACKET_SIZE_2]
        return [{
            "address" :         p1[:self.address_length].hex(),
            "payload" :         p1[:-self.crc_size].hex(),
            "crc" :             p1[-self.crc_size:].hex()
            },{
            "address" :         p2[:self.address_length].hex(),
            "payload" :         p2[:-self.crc_size].hex(),
            "crc" :             p2[-self.crc_size:].hex()
            },
        ]



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
        pass
    

    def build_clicks(self, clicks):
        """Build the click byte based on the clicks given.

        Args: 
            clicks (list[MouseClickType]): A list containing the pressed clicks.       
        
        Returns:
            bytes: The byte containing the correct value based on the pressed clicks.
        """
        pass
    

    def handle_sniffed_packet(self, packet, channel):
        for p in packet:
            if self.check_crc(p["crc"], p["payload"]):
                print(f"Cherry Mouse Packet\tCHANNEL : {channel}")
                print(p)
