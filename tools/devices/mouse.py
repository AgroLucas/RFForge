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

from enum import Enum

"""This module provides an enumerate that maps widely used USB HID code of mouse clicks.

"""

class MouseClickType(Enum):
    NO_CLICK        = 0x00
    LEFT_CLICK      = 0x01
    RIGHT_CLICK     = 0x02
    MIDDLE_CLICK    = 0x04