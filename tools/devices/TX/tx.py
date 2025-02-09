from lib import common
from devices.device import Device


class Tx(Device):
    ADDRESS_LENGTH = 4
    CHANNELS = [28, 35, 37, 42, 56, 68, 77, 40]
    RATE = common.RF_RATE_1M
    PACKET_SIZE = 16
    PREAMBLE = "FF:FF:FF:FF"
    CRC_SIZE = 2

    def __init__(self, address, crc=None):
        super().__init__(address, self.ADDRESS_LENGTH, self.CHANNELS, self.RATE, self.PACKET_SIZE, self.PREAMBLE, self.CRC_SIZE, crc)
