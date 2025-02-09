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


class Tlsr85(Device):
    """ Represents a TLSR85 keyboard or a TLSR85 mouse.
    
    Successfully tested with the Trust ODY II and the Poss PSKEY530BK.    
    """

    ADDRESS_LENGTH = 4
    CHANNELS = [5, 11, 17, 51, 57, 63, 69, 75]
    RATE = common.RF_RATE_2M
    CRC_SIZE = 2

    def __init__(self, address, packet_size, preamble, crc=None):
        super().__init__(address, self.ADDRESS_LENGTH, self.CHANNELS, self.RATE, packet_size, preamble, self.CRC_SIZE, crc)
