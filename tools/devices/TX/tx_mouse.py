import crcmod
from binascii import unhexlify

from devices.TX.tx import Tx
from devices.mouse import *

class Tx_mouse(Tx):

    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))


    def parse_packet(self, packet):
        p = packet[:self.packet_size]

        sequence_int = int.from_bytes(p[4:5], "big")
        sequence_number = hex((((sequence_int >> 2) & 1) << 1) | ((sequence_int >> 1) & 1)) # get 3rd and 2nd bits
        status_int = int.from_bytes(p[5:6], "big")
        status = hex((((status_int >> 2) & 1) << 1) | ((status_int >> 1) & 1))
        return {
            "address"           : p[:self.address_length].hex(),
            "payload"           : p[:-self.crc_size].hex(),
            "sequence_number"   : sequence_number,
            "status_number"     : status,
            "click_type"        : p[6:7].hex(),
            "scrolling"         : p[7:8].hex(),
            "x"                 : p[8:10].hex(),
            "y"                 : p[10:12].hex(),
            "crc"               : p[-self.crc_size:].hex()
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
    

    def handle_sniffed_packet(self, packet, channel):
        if self.check_crc(packet["crc"], packet["payload"]):
            print(f"TX Mouse Packet\tCHANNEL : {channel}")
            print(packet)
