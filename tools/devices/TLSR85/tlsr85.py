from abc import ABC, abstractmethod
from lib import common
from binascii import unhexlify

class Tlsr85(ABC):
    CHANNELS = [5, 11, 17, 51, 57, 63, 69, 75]
    RATE = common.RF_RATE_2M
    BASE_ADDRESS_LENGTH = 3
    FULL_ADDRESS_LENGTH = 4

    def __init__(self, base_address, crc=None):
        self.base_address = base_address
        self.crc = crc


    def check_crc(self, expected_crc, crc_input):
        return f"{self.crc(unhexlify(crc_input)):04x}" == expected_crc

    @abstractmethod
    def parse_packet(self, packet):
        pass

    def calculate_crc(self, crc_input):
        return self.crc(bytes(crc_input)).to_bytes(2, "big")
