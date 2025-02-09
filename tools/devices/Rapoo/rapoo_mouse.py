import crcmod
from binascii import unhexlify

from devices.Rapoo.rapoo import Rapoo
from devices.mouse import *

class Rapoo_Mouse(Rapoo):

    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 0


    def parse_packet(self, packet):
        p = packet[:self.packet_size]
        return {"address" :         p[:self.address_length].hex(),
                "payload" :         p[:-self.crc_size].hex(),
                "packet type" :     p[6:7].hex(),
                "sequence number":  p[7:8].hex(),
                "click" :           p[13:14].hex(),
                "x" :               p[14:16].hex(),
                "y" :               p[16:18].hex(),
                "scrolling":        p[18:19].hex(),
                "crc" :             p[-self.crc_size:].hex()
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
    

    def handle_sniffed_packet(self, packet, channel):
        if self.check_crc(packet["crc"], packet["payload"]):
            if packet["packet type"] == "04":
                print(f"Rapoo Mouse Packet\tCHANNEL : {channel}")
                print(packet)
