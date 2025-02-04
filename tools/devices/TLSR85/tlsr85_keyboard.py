import crcmod
from binascii import unhexlify

from devices.TLSR85.tlsr85 import Tlsr85
from devices.keyboard import * 
import time
from lib import common


class Tlsr85Keyboard(Tlsr85):


    def __init__(self, base_address, keyboard_address, preamble, packet_size, crc_poly, crc_init, crc_size):
        super().__init__(base_address, base_address + ":" + keyboard_address, preamble, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.keyboard_address = keyboard_address
        self.packet_size = packet_size
        self.crc_size = crc_size
        self.sequence_number = 0


    def parse_packet(self, packet):
        p = packet[:self.packet_size]
        modifiers = int.from_bytes(p[12:14], "big")
        return {"address" :         p[:self.FULL_ADDRESS_LENGTH].hex(),
                "payload" :         p[:-self.crc_size].hex(),
                "sequence number" : p[10:11].hex(),
                "array" :           [hex(item) for item in p[-(6+self.crc_size):-self.crc_size]],
                "crc" :             p[-self.crc_size:].hex(),
                "raw_modifiers":    modifiers,
                "modifiers" : {
                    "is left ctrl" :            (modifiers >> 0) & 1,
                    "is left shift" :           (modifiers >> 1) & 1,
                    "is left alt" :             (modifiers >> 2) & 1,
                    "is left gui" :             (modifiers >> 3) & 1,
                    "is right ctrl" :           (modifiers >> 4) & 1,
                    "is right shift" :          (modifiers >> 5) & 1,
                    "is right alt" :            (modifiers >> 6) & 1,
                    "is key pressed" :          (modifiers >> 8) & 1,
                    "is multiple key pressed" : (modifiers >> 9) & 1
                    }
                }
    

    def scancode_to_char(self, array, modifiers):
        is_key_pressed = (modifiers >> 8) & 1
        if not is_key_pressed:
            return ""
        is_shift = ((modifiers >> 1) & 1) or ((modifiers >> 5) & 1)
        is_altgr = (modifiers >> 6) & 1
        modifier = int(is_shift) + (2 * int(is_altgr))
        is_multiple_key_pressed = (modifiers >> 9) & 1
        if is_multiple_key_pressed:
            chars = ""
            for scancode in array:
                chars += KeyboardScancode.SCANCODE_TO_CHAR.value.get((int(scancode), modifier), "")
            return chars
        return KeyboardScancode.SCANCODE_TO_CHAR.value.get((int(array[0], 16), modifier), "")


    def build_packet(self, scancodes=[], modifiers=[]):
        address = unhexlify(self.full_address.replace(':', ''))
        beginning_payload = b"\x79\x51\x80\x02\x25\x05"
        sequence_number = self.sequence_number.to_bytes(1, "big")
        self.sequence_number = (self.sequence_number + 1) % 255
        padding = b"\x01"
        flags = self.build_flags(modifiers)
        array = self.build_array(scancodes)
        crc = self.calculate_crc(address+beginning_payload+sequence_number+padding+flags+array)

        return address+beginning_payload+sequence_number+padding+flags+array+crc
    

    def build_flags(self, modifiers):
        flags = 256 # key press is on by default
        for modifier in modifiers:
            if modifier in KeyboardModifiers:
                flags |= modifier.value
        return flags.to_bytes(2, "big")
    

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
        byte_full_address = unhexlify(self.full_address.replace(':', ''))

        channel_index = 0
        common.radio.set_channel(channels[channel_index]) # Set channel here to prevent USBError (somehow)
        common.radio.enter_promiscuous_mode_generic(byte_full_address, rate=self.RATE)
        last_tune = time.time()
        entered_string = ""

        while True:
            # Increment the channel after dwell_time
            if len(channels) > 1 and time.time() - last_tune > dwell_time:
                channel_index = (channel_index + 1) % (len(channels))
                common.radio.set_channel(channels[channel_index])
                last_tune = time.time()

            value = common.radio.receive_payload()
            if len(value) >= self.FULL_ADDRESS_LENGTH:
                found_address = bytes(value[:self.FULL_ADDRESS_LENGTH])
                if found_address == byte_full_address:            
                    packet = self.parse_packet(bytes(value))
                    if self.check_crc(packet["crc"], packet["payload"]):
                        print(f"TLSR85 Keyboard packet\tCHANNEL : {channels[channel_index]}")
                        entered_string += self.scancode_to_char(packet["array"], packet["raw_modifiers"])
                        print(entered_string)
                        last_tune = time.time()