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

class HP_Mouse(Device):
    """Represents an HP mouse.

    """
    ADDRESS_LENGTH = 4
    CHANNELS = [5, 26, 30, 42, 58, 71, 74]
    RATE = common.RF_RATE_1M
    PACKET_SIZE = 21
    PREAMBLE = "FF:EE"
    CRC_SIZE = 2


    # TODO change device.py to include multiple packet size and crcs
    # TODO sniff spoof not implemented
    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, self.ADDRESS_LENGTH, self.CHANNELS, self.RATE, self.PACKET_SIZE, self.PREAMBLE, self.CRC_SIZE, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 0
        self.crcs = [crcmod.mkCrcFun(0x11021, initCrc=0x5c3c, rev=False, xorOut=0x0000),
                crcmod.mkCrcFun(0x11021, initCrc=0x3e44, rev=False, xorOut=0x0000)]

    
    def check_crc(self, expected_crc, crc_input):
        for crc in self.crcs:
            if f"{crc(unhexlify(crc_input)):04x}" == expected_crc:
                return True
        return False


    def parse_packet(self, packet):
        p = packet[:self.PACKET_SIZE]
        
        return {
            "address" :         p[:self.address_length].hex(),
            "payload" :         p[:-self.crc_size].hex(),
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
        print(f"HP Mouse Packet\tCHANNEL : {channel}")
        print(packet)
        if self.check_crc(packet["crc"], packet["payload"]):
            return True
        return False
