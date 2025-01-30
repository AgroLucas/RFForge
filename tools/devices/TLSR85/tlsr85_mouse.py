import crcmod

from devices.TLSR85.tlsr85 import Tlsr85


class Tlsr85Mouse(Tlsr85):
    MOUSE_ADDRESS_LENGTH = 1

    def __init__(self, base_address, mouse_address, packet_size, crc_poly, crc_init, crc_size):
        super().__init__(base_address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.mouse_address = mouse_address
        self.packet_size = packet_size
        self.crc_size = crc_size


    def parse_packet(self, packet):
        pass
