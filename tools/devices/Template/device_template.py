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

from lib import common
from devices.device import Device
from devices.mouse import *
from devices.keyboard import * 

class Template(Device):
    """Template class for a device

    """
    ADDRESS_LENGTH = 3 # the nRF dongle supports up to 5-byte address
    CHANNELS = []
    RATE = common.RF_RATE_1M # can also be common.RF_RATE_2M or common.RF_RATE_250K
    PACKET_SIZE = 0
    PREAMBLE = "AA:AA"
    CRC_SIZE = 2



    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, self.ADDRESS_LENGTH, self.CHANNELS, self.RATE, self.PACKET_SIZE, self.PREAMBLE, self.CRC_SIZE, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))


    def parse_packet(self, packet):
        """This method is required for sniffing. It allows for a better visualization of the protocols' fields. The pydoc is available in the device.py file
        Other fields can be added such as click type, x, y for mice and array, modifiers for keyboards
        
        """
        p = packet[:self.packet_size]
        return {
            "address" : p[:self.address_length].hex(),
            "payload" : p[:-self.crc_size].hex(),
            "crc" :     p[-self.crc_size:].hex()
            }
        

    def handle_sniffed_packet(self, packet, channel):
        """ This method is required for sniffing. It displays information about the packet. The pydoc is available in the device.py file
        Additional checks about the packets can be done before displaying it.
        
        """
        if self.check_crc(packet["crc"], packet["payload"]):
            print(f"Packet\tCHANNEL : {channel}")
            print(packet)
            return True
        return False


    def build_packet(self, scancodes=[]):
        """Build a raw keyboard packet based on the scancodes given.

        Args: 
            scancodes (list[KeyboardScancode]): A list of KeyboardScancode to include in the packet.

        Returns:
            bytes: A raw packet in bytes format (it does not contain the preamble).
        """
        address = unhexlify(self.address.replace(':', ''))
        #TODO create the remaining fields, add them as parameters to the calculate_crc function AND to the final return. The output of this function should have a similar structure to the input of the parse_packet function
        crc = self.calculate_crc(address)
        
        return address+crc


    def build_packet(self, clicks, x_move="0000", y_move="0000", scrolling_move="00"):
        """Build a raw mouse packet.

        Args: 
            clicks (list[MouseClickType]): A list of MouseClickType to include in the packet.
            x_move (str): The movement of the mouse in the x axis in hexadecimal string.
            y_move (str): The movement of the mouse in the y axis in hexadecimal string.
            scrolling_move (str): The movement of the wheel in signed hexadecimal string.

        Returns:
            bytes: A raw packet in bytes format (it does not contain the preamble).
        """
        address = unhexlify(self.address.replace(':', ''))
        #TODO create the remaining fields, add them as parameters to the calculate_crc function AND to the final return. The output of this function should have a similar structure to the input of the parse_packet function
        crc = self.calculate_crc(address)

        return address+crc
    
