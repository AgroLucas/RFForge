import crcmod
from binascii import unhexlify

from devices.TLSR85.tlsr85 import Tlsr85


class Tlsr85Mouse(Tlsr85):
    PACKET_SIZE = 30

    def __init__(self, address, preamble, crc_poly, crc_init):
        super().__init__(address, self.PACKET_SIZE, preamble, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 133


    def parse_packet(self, packet):
        p = packet[:self.packet_size]
        return {"address" :         p[:self.address_length].hex(),
                "payload" :         p[:-self.crc_size].hex(),
                "sequence number":  p[10:11].hex(),
                "click type":       p[12:13].hex(),
                "x_y_movement":     p[13:15].hex(),
                "scrolling":        p[15:16].hex(),
                "crc" :             p[-self.crc_size:].hex()
                }


    # TODO hardcoded, currently not working
    def build_packet(self, click_types=[], scrolling=None, x=None, y=None):
        address = unhexlify(self.address.replace(':', ''))
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


    def handle_sniffed_packet(self, packet, channel):
        if self.check_crc(packet["crc"], packet["payload"]):
            print(f"TLSR85 Mouse Packet\tCHANNEL : {channel}")
            print(packet)
