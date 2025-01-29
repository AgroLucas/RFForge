from abc import ABC, abstractmethod
from tools.lib import common


class Tlsr85(ABC):
    CHANNELS = [5, 11, 17, 51, 57, 63, 69, 75]
    RATE = common.RF_RATE_2M
    BASE_ADDRESS_LENGTH = 3
    FULL_ADDRESS_LENGTH = 4

    def __init__(self, base_address, crc16):
        self.base_address = base_address
        self.crc16 = crc16

    # TODO check the type of parameters
    def check_crc(self, expected_crc, crc_input):
        return f"{self.crc16(bytes(crc_input)):04x}" == bytes(expected_crc).hex()

    @abstractmethod
    def parse_packet(self, packet):
        pass
