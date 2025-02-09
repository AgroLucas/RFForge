import crcmod
from binascii import unhexlify

from devices.Rapoo.rapoo import Rapoo
from devices.keyboard import * 


class Rapoo_Keyboard(Rapoo):


    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 0


    def parse_packet(self, packet):
        p = packet[:self.packet_size]
        return {"address" :         p[:self.address_length].hex(),
                "payload" :         p[:-self.crc_size].hex(),
                "packet type" :     p[6:7].hex(),
                "sequence number":  p[7:8].hex(),
                "array":            [hex(item) for item in p[-(6+self.crc_size):-self.crc_size]],
                "crc" :             p[-self.crc_size:].hex()
                }
    

    def scancode_to_char(self, array):
        modifiers = 0
        shifted = False
        for scancode in array: # grab potential modifiers
            value = int(scancode, 16)
            if value == KeyboardScancode.KEY_LSHIFT.value or value == KeyboardScancode.KEY_RSHIFT.value and not shifted:
                modifiers += 1
                shifted = True # avoid incrementing modifier 2 times in case we press L and R shift at the same time
            elif value == KeyboardScancode .KEY_RALT.value:
                modifiers += 2
        chars = ""
        for scancode in array:
            chars += KeyboardScancode.SCANCODE_TO_CHAR.value.get((int(scancode, 16), modifiers), "")
        return chars


    def build_packet(self, scancodes=[]):
        address = unhexlify(self.address.replace(':', ''))
        beginning_payload = b"\xdc\x69\x06"
        sequence_number = self.sequence_number.to_bytes(1, "big")
        self.sequence_number = (self.sequence_number + 1) % 255
        padding = b"\x01\x02\xea\x3a\x16"
        array = self.build_array(scancodes)
        crc = self.calculate_crc(address+beginning_payload+sequence_number+padding+array)
        
        return address+beginning_payload+sequence_number+padding+array+crc
    

    def build_array(self, scancodes):
        array = b""
        for i in range(len(scancodes)):
            if i == 6 :
                break
            if scancodes[i] in KeyboardScancode:
                array += scancodes[i].value.to_bytes(1, "big")
        array += unhexlify("00" * (6 - len(scancodes)))
        return array
    

    def handle_sniffed_packet(self, packet, channel):
        if self.check_crc(packet["crc"], packet["payload"]):
            if packet["packet type"] == "06":
                print(f"Rapoo Keyboard Packet\tCHANNEL : {channel}")
                print(packet)
                print(self.scancode_to_char(packet["array"]))

    