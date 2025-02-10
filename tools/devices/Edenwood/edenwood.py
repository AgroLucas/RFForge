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


class Edenwood(Device):
    """Represents a Edenwood keyboard or a Edenwood mouse.
    
    Successfully tested with the 963716 CWL01 mouse and keyboard.
    """

    ADDRESS_LENGTH = 4
    CHANNELS = [20, 40, 54, 81]
    RATE = common.RF_RATE_2M
    PACKET_SIZE = 19
    PREAMBLE = "62:62:62:7F"
    CRC_SIZE = 2

    def __init__(self, address, crc=None):
        super().__init__(address, self.ADDRESS_LENGTH, self.CHANNELS, self.RATE, self.PACKET_SIZE, self.PREAMBLE, self.CRC_SIZE, crc)
