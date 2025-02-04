import crcmod
from enum import Enum
from binascii import unhexlify
import time
from lib import common



from devices.TLSR85.tlsr85 import Tlsr85


class Tlsr85Mouse(Tlsr85):
    MOUSE_ADDRESS_LENGTH = 1

    def __init__(self, base_address, mouse_address, preamble, packet_size, crc_poly, crc_init, crc_size):
        super().__init__(base_address, base_address + ":" + mouse_address, preamble, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.mouse_address = mouse_address
        self.packet_size = packet_size
        self.crc_size = crc_size
        self.sequence_number = 133


    def parse_packet(self, packet):
        p = packet[:self.packet_size]
        return {"address" :         p[:self.FULL_ADDRESS_LENGTH].hex(),
                "payload" :         p[:-self.crc_size].hex(),
                "sequence number":  p[10:11].hex(),
                "click type":       p[12:13].hex(),
                "x_y_movement":     p[13:15].hex(),
                "scrolling":        p[15:16].hex(),
                "crc" :             p[-self.crc_size:].hex()
                }


    # TODO hardcoded, currently not working
    def build_packet(self, click_types=[], scrolling=None, x=None, y=None):
        address = unhexlify(self.full_address.replace(':', ''))
        beginning_payload = b"\xb9\x51\x65\x01\x35\x36"
        sequence_number = self.sequence_number.to_bytes(1, "big")
        self.sequence_number = (self.sequence_number + 1) % 255
        padding = b"\x01"
        click = b"\x02"
        x = b"\x00"
        y = b"\x00"
        scroll = b"\x00"
        big_padding = b"\x02\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00"
        crc = self.calculate_crc(address + beginning_payload + sequence_number + padding + click + x + y + scroll + big_padding)
        
        return address + beginning_payload + sequence_number + padding + click + x + y + scroll + big_padding + crc


    def sniff(self):
        dwell = 200
        dwell_time = dwell / 1000
        channels = self.CHANNELS
        byte_full_address = unhexlify(self.full_address.replace(':', ''))

        channel_index = 0
        common.radio.set_channel(channels[channel_index]) # Set channel here to prevent USBError (somehow)
        common.radio.enter_promiscuous_mode_generic(byte_full_address, rate=self.RATE)
        last_tune = time.time()

        while True:
            # Increment the channel after dwell_time
            if len(channels) > 1 and time.time() - last_tune > dwell_time:
                channel_index = (channel_index + 1) % (len(channels))
                common.radio.set_channel(channels[channel_index])
                last_tune = time.time()

            value = common.radio.receive_payload()
            if len(value) >= self.FULL_ADDRESS_LENGTH:
                found_address = bytes(value[:self.FULL_ADDRESS_LENGTH])
                if found_address == byte_full_address:            
                    packet = self.parse_packet(bytes(value))
                    if self.check_crc(packet["crc"], packet["payload"]):
                        print(f"TLSR85 Mouse packet\tCHANNEL : {channels[channel_index]}")
                        print(packet)
                        last_tune = time.time()
