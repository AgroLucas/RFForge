import crcmod

from devices.TLSR85.tlsr85 import Tlsr85


class Tlsr85Dongle(Tlsr85):

    def __init__(self, base_address, packet_size, crc_poly, crc_init1, crc_init2, crc_size):
        super().__init__(base_address)
        self.packet_size = packet_size
        self.crcs = [crcmod.mkCrcFun(crc_poly, initCrc=crc_init1, rev=False, xorOut=0x0000),
                    crcmod.mkCrcFun(crc_poly, initCrc=crc_init2, rev=False, xorOut=0x0000)]
        self.crc_size = crc_size

    def check_crc(self, expected_crc, crc_input):
        for crc in self.crcs :
            if f"{crc(bytes(crc_input)):04x}" == bytes(expected_crc).hex():
                return True
        return False

    def parse_packet(self, packet):
        pass
