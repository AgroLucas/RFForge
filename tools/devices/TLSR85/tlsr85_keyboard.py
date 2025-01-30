import crcmod
from enum import Enum
from binascii import unhexlify

from devices.TLSR85.tlsr85 import Tlsr85

# TODO add every scancode
class Tlsr85KeyboardScancode(Enum):
    NUM_1 = "59"
    NUM_2 = "5A"
    NUM_3 = "5B"
    NUM_4 = "5C"
    NUM_5 = "5D"
    NUM_6 = "5E"
    NUM_7 = "5F"
    NUM_8 = "60"
    NUM_9 = "61"
    NUM_0 = "62"


class Tlsr85Keyboard(Tlsr85):


    def __init__(self, base_address, keyboard_address, packet_size, crc_poly, crc_init, crc_size):
        super().__init__(base_address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.keyboard_address = keyboard_address
        self.full_address = base_address + ":" + keyboard_address
        self.packet_size = packet_size
        self.crc_size = crc_size
        self.start_array_index = 6*8
        self.sequence_number = 0


    # TODO parse modifiers (shift, alt, ctrl, ...)
    def parse_packet(self, packet):
        p = packet[:self.packet_size]
        return {"address": p[:super().FULL_ADDRESS_LENGTH],
                "payload" : p[:-self.crc_size],
                "array" : [str(item) for item in p[-(6+self.crc_size):-self.crc_size]],
                "crc" : p[-self.crc_size:]
                }


    # TODO add support for modifiers
    def build_packet(self, scancodes):
        address = unhexlify(self.full_address.replace(':', ''))
        beginning_payload = b"\x79\x51\x80\x02\x25\x05"
        sequence_number = self.sequence_number.to_bytes(1, "big")
        self.sequence_number = (self.sequence_number + 1) % 255
        padding = b"\x01"
        modifiers = b"\x01\x00"
        array = self.build_array(scancodes)
        crc = self.calculate_crc(address+beginning_payload+sequence_number+padding+modifiers+array)

        return address+beginning_payload+sequence_number+padding+modifiers+array+crc
    

    # TODO make it work with multiple scancodes at the same time, currently only the first scancode works (likely flag somewhere to change ?)
    def build_array(self, scancodes):
        array = ""
        for i in range(len(scancodes)):
            if scancodes[i] in Tlsr85KeyboardScancode:
                array += scancodes[i].value
        array += "00" * (6 - len(scancodes))
        return bytes.fromhex(array)
