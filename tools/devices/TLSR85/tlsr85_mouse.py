import crcmod

from devices.TLSR85.tlsr85 import Tlsr85


class Tlsr85Mouse(Tlsr85):
    MOUSE_ADDRESS_LENGTH = 1

    def __init__(self, base_address, mouse_address, preamble, packet_size, crc_poly, crc_init, crc_size):
        super().__init__(base_address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.mouse_address = mouse_address
        self.preamble = preamble
        self.packet_size = packet_size
        self.crc_size = crc_size

    # TODO
    def parse_packet(self, packet):
        p = packet[:self.packet_size]
        print(p.hex())
        return {"address" :         p[:self.FULL_ADDRESS_LENGTH].hex(),
                "payload" :         p[:-self.crc_size].hex(),
                "crc" :             p[-self.crc_size:].hex()
                }
