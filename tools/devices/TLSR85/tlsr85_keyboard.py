import crcmod

from tools.devices.TLSR85.tlsr85 import Tlsr85


class Tlsr85Keyboard(Tlsr85):


    def __init__(self, base_address, keyboard_address, packet_size, crc_poly, crc_init, crc_size):
        super().__init__(base_address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.keyboard_address = keyboard_address
        self.packet_size = packet_size
        self.crc_size = crc_size
        self.start_array_index = 6*8


    def parse_packet(self, packet):
        # extract address, payload(everything except crc), crc, array
        # later also extract flags for shift, alt, ctrl, ...
        return {"address": packet[:super().FULL_ADDRESS_LENGTH],
                "payload" : packet[:-self.crc_size],
                "array" : [str(item) for item in packet[-(48+self.crc_size):-self.crc_size]],
                "crc" : packet[-self.crc_size:]
                }

