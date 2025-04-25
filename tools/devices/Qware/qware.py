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

from lib import common
from devices.device import Device


class Qware(Device):
    """Represents a Qware keyboard or a Qware mouse.
    
    Successfully tested with the QW PCB-238BL mouse and keyboard.
    """

    ADDRESS_LENGTH = 5
    CHANNELS = [2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 62, 66, 68, 70, 72, 74, 78, 80, 82] # checked with fuzz_channels()
    RATE = common.RF_RATE_2M
    PREAMBLE = "AA:AA"
    CRC_SIZE = 2

    def __init__(self, address, packet_size, crc=None):
        super().__init__(address, self.ADDRESS_LENGTH, self.CHANNELS, self.RATE, packet_size, self.PREAMBLE, self.CRC_SIZE, crc)
