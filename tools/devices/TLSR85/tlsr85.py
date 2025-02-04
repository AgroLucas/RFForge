from abc import ABC, abstractmethod
from lib import common
from binascii import unhexlify
import time

class Tlsr85(ABC):
    CHANNELS = [5, 11, 17, 51, 57, 63, 69, 75]
    RATE = common.RF_RATE_2M
    BASE_ADDRESS_LENGTH = 3
    FULL_ADDRESS_LENGTH = 4

    def __init__(self, base_address, full_address, preamble, crc=None):
        self.base_address = base_address
        self.full_address = full_address
        self.preamble = preamble
        self.crc = crc


    def check_crc(self, expected_crc, crc_input):
        return f"{self.crc(unhexlify(crc_input)):04x}" == expected_crc
    

    def calculate_crc(self, crc_input):
        return self.crc(bytes(crc_input)).to_bytes(2, "big")


    @abstractmethod
    def parse_packet(self, packet):
        pass


    @abstractmethod
    def build_packet(self, scancode=[], modifiers=[]):
        pass


    @abstractmethod
    def sniff(self):
        pass
    

    def spoof(self, attack):
        address = unhexlify(self.full_address.replace(':', ''))
        preamble = unhexlify(self.preamble.replace(':', ''))
        channel_index = 0
        common.radio.set_channel(self.CHANNELS[channel_index]) # Set channel here to prevent USBError (somehow)
        common.radio.enter_promiscuous_mode_generic(address, rate=self.RATE)
        for payload in attack:
            if callable(payload):
                payload() # in case we want a delay
            else:
                for i in range(len(self.CHANNELS)):
                    common.radio.set_channel(self.CHANNELS[i])
                    for _ in range(30):
                        common.radio.transmit_payload_generic(payload=preamble+payload, address=address)
                        time.sleep(0.00001)
