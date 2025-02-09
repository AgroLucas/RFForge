from lib import common
from devices.device import Device

class Rapoo(Device):
    ADDRESS_LENGTH = 4
    CHANNELS = [22, 34, 43, 56, 67, 78]
    RATE = common.RF_RATE_2M
    PACKET_SIZE = 21
    PREAMBLE = "00:AA:AA"
    CRC_SIZE = 2

    def __init__(self, address, crc):
        super().__init__(address, self.ADDRESS_LENGTH, self.CHANNELS, self.RATE, self.PACKET_SIZE, self.PREAMBLE, self.CRC_SIZE, crc)
