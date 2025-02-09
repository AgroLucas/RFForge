from binascii import unhexlify
import time
from lib import common
from devices.device import Device


class Tlsr85(Device):
    ADDRESS_LENGTH = 4
    CHANNELS = [5, 11, 17, 51, 57, 63, 69, 75]
    RATE = common.RF_RATE_2M
    CRC_SIZE = 2

    def __init__(self, address, packet_size, preamble, crc=None):
        super().__init__(address, self.ADDRESS_LENGTH, self.CHANNELS, self.RATE, packet_size, preamble, self.CRC_SIZE, crc)
