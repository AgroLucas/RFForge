import crcmod
from enum import Enum
from binascii import unhexlify

from devices.TLSR85.tlsr85 import Tlsr85


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
            if modifier in Tlsr85KeyboardModifiers:
                flags |= modifier.value
        return flags.to_bytes(2, "big")
    

    # TODO make it work with multiple scancodes at the same time, currently only the first scancode works (likely flag somewhere to change ?)
    def build_array(self, scancodes):
        array = b""
        for i in range(len(scancodes)):
            if i == 6 :
                break
            if scancodes[i] in Tlsr85KeyboardScancode:
                array += scancodes[i].value.to_bytes(1, "big")
        array += unhexlify("00" * (6 - len(scancodes)))
        return array
    
    

# TODO add support for 'key press' and 'multiple keys'
class Tlsr85KeyboardModifiers(Enum):
    MODIFIER_NONE           = 0
    MODIFIER_CONTROL_LEFT   = 1 << 0
    MODIFIER_SHIFT_LEFT     = 1 << 1
    MODIFIER_ALT_LEFT       = 1 << 2
    MODIFIER_GUI_LEFT       = 1 << 3
    MODIFIER_CONTROL_RIGHT  = 1 << 4
    MODIFIER_SHIFT_RIGHT    = 1 << 5
    MODIFIER_ALT_RIGHT      = 1 << 6
    MODIFIER_GUI_RIGHT      = 1 << 7


# TODO adapt scancodes for Belgian keyboard
class Tlsr85KeyboardScancode(Enum):

    KEY_NONE                = 0x00
    KEY_A                   = 0x04
    KEY_B                   = 0x05
    KEY_C                   = 0x06
    KEY_D                   = 0x07
    KEY_E                   = 0x08
    KEY_F                   = 0x09
    KEY_G                   = 0x0A
    KEY_H                   = 0x0B
    KEY_I                   = 0x0C
    KEY_J                   = 0x0D
    KEY_K                   = 0x0E
    KEY_L                   = 0x0F
    KEY_M                   = 0x33
    KEY_N                   = 0x11
    KEY_O                   = 0x12
    KEY_P                   = 0x13
    KEY_Q                   = 0x14
    KEY_R                   = 0x15
    KEY_S                   = 0x16
    KEY_T                   = 0x17
    KEY_U                   = 0x18
    KEY_V                   = 0x19
    KEY_W                   = 0x1A
    KEY_X                   = 0x1B
    KEY_Y                   = 0x1C
    KEY_Z                   = 0x1D
    KEY_1                   = 0x1E
    KEY_2                   = 0x1F
    KEY_3                   = 0x20
    KEY_4                   = 0x21
    KEY_5                   = 0x22
    KEY_6                   = 0x23
    KEY_7                   = 0x24
    KEY_8                   = 0x25
    KEY_9                   = 0x26
    KEY_0                   = 0x27
    KEY_RETURN              = 0x28
    KEY_ESCAPE              = 0x29
    KEY_BACKSPACE           = 0x2A
    KEY_TAB                 = 0x2B
    KEY_SPACE               = 0x2C
    KEY_MINUS               = 0x2D
    KEY_EQUAL               = 0x2E
    KEY_BRACKET_LEFT        = 0x2F
    KEY_BRACKET_RIGHT       = 0x30
    KEY_BACKSLASH           = 0x31
    KEY_EUROPE_1            = 0x32
    KEY_SEMICOLON           = 0x33
    KEY_APOSTROPHE          = 0x34
    KEY_GRAVE               = 0x35
    KEY_COMMA               = 0x10
    KEY_PERIOD              = 0x37
    KEY_SLASH               = 0x38
    KEY_CAPS_LOCK           = 0x39
    KEY_F1                  = 0x3A
    KEY_F2                  = 0x3B
    KEY_F3                  = 0x3C
    KEY_F4                  = 0x3D
    KEY_F5                  = 0x3E
    KEY_F6                  = 0x3F
    KEY_F7                  = 0x40
    KEY_F8                  = 0x41
    KEY_F9                  = 0x42
    KEY_F10                 = 0x43
    KEY_F11                 = 0x44
    KEY_F12                 = 0x45
    KEY_PRINT_SCREEN        = 0x46
    KEY_SCROLL_LOCK         = 0x47
    KEY_PAUSE               = 0x48
    KEY_INSERT              = 0x49
    KEY_HOME                = 0x4A
    KEY_PAGE_UP             = 0x4B
    KEY_DELETE              = 0x4C
    KEY_END                 = 0x4D
    KEY_PAGE_DOWN           = 0x4E
    KEY_ARROW_RIGHT         = 0x4F
    KEY_ARROW_LEFT          = 0x50
    KEY_ARROW_DOWN          = 0x51
    KEY_ARROW_UP            = 0x52
    KEY_NUM_LOCK            = 0x53
    KEY_KEYPAD_DIVIDE       = 0x54
    KEY_KEYPAD_MULTIPLY     = 0x55
    KEY_KEYPAD_SUBTRACT     = 0x56
    KEY_KEYPAD_ADD          = 0x57
    KEY_KEYPAD_ENTER        = 0x58
    KEY_KEYPAD_1            = 0x59
    KEY_KEYPAD_2            = 0x5A
    KEY_KEYPAD_3            = 0x5B
    KEY_KEYPAD_4            = 0x5C
    KEY_KEYPAD_5            = 0x5D
    KEY_KEYPAD_6            = 0x5E
    KEY_KEYPAD_7            = 0x5F
    KEY_KEYPAD_8            = 0x60
    KEY_KEYPAD_9            = 0x61
    KEY_KEYPAD_0            = 0x62
    KEY_KEYPAD_DECIMAL      = 0x63
    KEY_EUROPE_2            = 0x64
    KEY_APPLICATION         = 0x65
    KEY_POWER               = 0x66
    KEY_KEYPAD_EQUAL        = 0x67
    KEY_F13                 = 0x68
    KEY_F14                 = 0x69
    KEY_F15                 = 0x6A
    KEY_CONTROL_LEFT        = 0xE0
    KEY_SHIFT_LEFT          = 0xE1
    KEY_ALT_LEFT            = 0xE2
    KEY_GUI_LEFT            = 0xE3
    KEY_CONTROL_RIGHT       = 0xE4
    KEY_SHIFT_RIGHT         = 0xE5
    KEY_ALT_RIGHT           = 0xE6
    KEY_GUI_RIGHT           = 0xE7