from abc import ABC, abstractmethod
from binascii import unhexlify
from lib import common
import time


class Device(ABC):

    def __init__(self, address, address_length, channels, rate, packet_size, preamble, crc_size, crc):
        self.address = address
        self.address_length = address_length
        self.channels = channels
        self.rate = rate
        self.packet_size = packet_size
        self.preamble = preamble
        self.crc_size = crc_size
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
    def handle_sniffed_packet(packet, channel):
        pass


    def sniff(self):
        dwell_time = 0.2
        channel_index = 0
        common.radio.set_channel(self.channels[channel_index]) # Set channel here to prevent USBError (somehow)
        common.radio.enter_promiscuous_mode_generic(unhexlify(self.address.replace(':', '')), rate=self.rate)
        last_tune = time.time()

        while True:
            # Increment the channel after dwell_time
            if len(self.channels) > 1 and time.time() - last_tune > dwell_time:
                channel_index = (channel_index + 1) % (len(self.channels))
                common.radio.set_channel(self.channels[channel_index])
                last_tune = time.time()

            value = common.radio.receive_payload()
            if len(value) >= self.address_length:
                if bytes(value[:self.address_length]) == unhexlify(self.address.replace(':', '')):    
                    self.handle_sniffed_packet(self.parse_packet(bytes(value)), self.channels[channel_index])
                    last_tune = time.time()
    
    
    def spoof(self, attack):
        address = unhexlify(self.address.replace(':', ''))
        preamble = unhexlify(self.preamble.replace(':', ''))
        channel_index = 0
        common.radio.set_channel(self.channels[channel_index]) # Set channel here to prevent USBError (somehow)
        common.radio.enter_promiscuous_mode_generic(address, rate=self.rate)
        for payload in attack: # send payload multiple time on every channels
            if callable(payload):
                payload() # in case we want a delay
            else:
                for i in range(len(self.channels)):
                    common.radio.set_channel(self.channels[i])
                    for _ in range(30):
                        common.radio.transmit_payload_generic(payload=preamble+payload, address=address)
                        time.sleep(0.00001)
