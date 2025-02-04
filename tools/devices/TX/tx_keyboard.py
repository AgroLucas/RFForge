import crcmod
from lib import common
from binascii import unhexlify
import time

from devices.TX.tx import Tx
from devices.keyboard import * 

class Tx_Keyboard(Tx):

    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))


    # TODO
    def parse_packet(self, packet):
        p = packet[:self.PACKET_SIZE]
        pass


    def build_packet(self, scancodes=[], modifiers=[]):
        packets = []
        address = unhexlify(self.address.replace(':', ''))

        for i in range (2): # send key down and key up
            status_byte = b"\x03"
            padding = b"\x00\x01"
            if i == 0:
                flags = self.build_flags(modifiers)
                array = self.build_array(scancodes)
                sequence_number_byte = b"\x49"
            else:
                flags = b"\x00"
                array = b"\x00\x00\x00\x00\x00"
                sequence_number_byte = b"\x4B"
            crc = self.calculate_crc(address+sequence_number_byte+status_byte+flags+array+padding)
            packets.append(address+sequence_number_byte+status_byte+flags+array+padding+crc)
        return packets
    
    
    def build_array(self, scancodes):
        array = b""
        for i in range(len(scancodes)):
            if i == 6 :
                break
            if scancodes[i] in KeyboardScancode:
                array += scancodes[i].value.to_bytes(1, "big")
        array += unhexlify("00" * (5 - len(scancodes)))
        return array


    def build_flags(self, modifiers):
        flags = 0 # key press is off by default
        for modifier in modifiers:
            if modifier in KeyboardModifiers:
                flags |= modifier.value
        return flags.to_bytes(1, "big")
    

    # TODO
    def sniff(self):
        pass