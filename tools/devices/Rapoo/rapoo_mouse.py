import crcmod
from lib import common
from binascii import unhexlify
import time

from devices.Rapoo.rapoo import Rapoo
from devices.mouse import *

class Rapoo_Mouse(Rapoo):

    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 0


    def parse_packet(self, packet):
        p = packet[:self.PACKET_SIZE]
        return {"address" :         p[:self.ADDRESS_LENGTH].hex(),
                "payload" :         p[:-self.CRC_SIZE].hex(),
                "packet type" :     p[6:7].hex(),
                "sequence number":  p[7:8].hex(),
                "click" :           p[13:14].hex(),
                "x" :               p[14:16].hex(),
                "y" :               p[16:18].hex(),
                "scrolling":        p[18:19].hex(),
                "crc" :             p[-self.CRC_SIZE:].hex()
                }


    def build_packet(self, clicks, x_move="0000", y_move="0000", scrolling_move="00"):
        address = unhexlify(self.address.replace(':', ''))
        beginning_payload = b"\xdc\x69\x04"
        sequence_number = self.sequence_number.to_bytes(1, "big")
        self.sequence_number = (self.sequence_number + 1) % 255
        padding = b"\x01\x01\x4c\xa2\x2e"
        click_type = self.build_clicks(clicks)
        x = unhexlify(x_move)
        y = unhexlify(y_move)
        scrolling = unhexlify(scrolling_move)
        crc = self.calculate_crc(address+beginning_payload+sequence_number+padding+click_type+x+y+scrolling)

        return address+beginning_payload+sequence_number+padding+click_type+x+y+scrolling+crc
    

    def build_clicks(self, clicks):
        click_result = 0
        for click in clicks:
            if click in MouseClickType:
                click_result |= click.value
        return click_result.to_bytes(1, "big")


    def sniff(self):
        dwell = 200
        dwell_time = dwell / 1000

        channels = self.CHANNELS
        #channels = range(0,84) # for fuzzing
        byte_address = unhexlify(self.address.replace(':', ''))

        channel_index = 0
        common.radio.set_channel(channels[channel_index]) # Set channel here to prevent USBError (somehow)
        common.radio.enter_promiscuous_mode_generic(unhexlify(self.address.replace(':', '')), rate=self.RATE)
        last_tune = time.time()


        while True:
            # Increment the channel after dwell_time
            if len(channels) > 1 and time.time() - last_tune > dwell_time:
                channel_index = (channel_index + 1) % (len(channels))
                common.radio.set_channel(channels[channel_index])
                last_tune = time.time()

            value = common.radio.receive_payload()
            if len(value) >= self.ADDRESS_LENGTH:
                found_base_address = bytes(value[:self.ADDRESS_LENGTH])
                if found_base_address == byte_address:
                    packet = self.parse_packet(bytes(value))
                    if self.check_crc(packet["crc"], packet["payload"]):
                        if packet["packet type"] == "04":
                            print(f"Rapoo Mouse Packet\tCHANNEL : {channels[channel_index]}")
                            print(packet)
                            last_tune = time.time()
