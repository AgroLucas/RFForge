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


from lib import common
from devices.device import Device
from devices.mouse import *

class Cherry(Device):
    """Represents a Cherry device.

    """
    ADDRESS_LENGTH = 3
    CHANNELS = range(0,100)
    RATE = common.RF_RATE_1M
    PACKET_SIZE = 21
    PREAMBLE = "AA:AA"
    CRC_SIZE = 0



    def __init__(self, address):
        super().__init__(address, self.ADDRESS_LENGTH, self.CHANNELS, self.RATE, self.PACKET_SIZE, self.PREAMBLE, self.CRC_SIZE, None)


    def parse_packet(self, packet):
        return {
            "address" : packet[:self.address_length].hex(),
            "payload" : packet[self.address_length:self.packet_size].hex(),
            "all" :     packet[:self.packet_size].hex()
            }
        
    

    def handle_sniffed_packet(self, packet, channel):
        if packet["all"][12:14] == "ff": # ignore dongle packets
            return
        print(f"Cherry Keyboard Packet\tCHANNEL : {channel}")
        print(packet)
        return True
    
