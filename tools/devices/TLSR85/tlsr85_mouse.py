import crcmod
from enum import Enum
from binascii import unhexlify


from devices.TLSR85.tlsr85 import Tlsr85


class Tlsr85Mouse(Tlsr85):
    MOUSE_ADDRESS_LENGTH = 1

    def __init__(self, base_address, mouse_address, preamble, packet_size, crc_poly, crc_init, crc_size):
        super().__init__(base_address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.mouse_address = mouse_address
        self.full_address = base_address + ":" + mouse_address
        self.preamble = preamble
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



class Tlsr85MouseClickType(Enum):
    LEFT_CLICK      = 0x01
    RIGHT_CLICK     = 0x02
    MIDDLE_CLICK    = 0x04