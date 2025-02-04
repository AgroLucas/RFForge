import crcmod
from lib import common
from binascii import unhexlify
import time

from devices.TX.tx import Tx
from devices.mouse import *

class Tx_mouse(Tx):

    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))


    def parse_packet(self, packet):
        p = packet[:self.PACKET_SIZE]

        sequence_int = int.from_bytes(p[4:5], "big")
        sequence_number = hex((((sequence_int >> 2) & 1) << 1) | ((sequence_int >> 1) & 1)) # get 3rd and 2nd bits
        status_int = int.from_bytes(p[5:6], "big")
        status = hex((((status_int >> 2) & 1) << 1) | ((status_int >> 1) & 1))
        return {
            "address"           : p[:self.ADDRESS_LENGTH].hex(),
            "payload"           : p[:-self.CRC_SIZE].hex(),
            "sequence_number"   : sequence_number,
            "status_number"     : status,
            "click_type"        : p[6:7].hex(),
            "scrolling"         : p[7:8].hex(),
            "x"                 : p[8:10].hex(),
            "y"                 : p[10:12].hex(),
            "crc"               : p[-self.CRC_SIZE:].hex()
        }


    def build_packet(self, clicks, x_move="0000", y_move="0000", scrolling_move="00"):
        packets = []
        address = unhexlify(self.address.replace(':', ''))

        for i in range(2):
            padding = b"\x33\xF1"
            if i == 0:
                status_byte = b"\x02"
                sequence_number_byte = b"\x49"
                x = unhexlify(x_move)
                y = unhexlify(y_move)
                click_type = self.build_clicks(clicks)
                scrolling = unhexlify(scrolling_move)
            else:
                status_byte = b"\x04"
                sequence_number_byte = b"\x4B"
                x = b"\x00\x00"
                y = b"\x00\x00"
                click_type = b"\x00"
                scrolling = b"\x00"
            crc = self.calculate_crc(address+sequence_number_byte+status_byte+click_type+scrolling+x+y+padding)
            packets.append(address+sequence_number_byte+status_byte+click_type+scrolling+x+y+padding+crc)
        return packets
    

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
                        print(f"Mouse packet\tCHANNEL : {channels[channel_index]}")
                        print(packet)
                        last_tune = time.time() 
