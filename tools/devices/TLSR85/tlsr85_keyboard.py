import crcmod
from enum import Enum
from binascii import unhexlify

from devices.TLSR85.tlsr85 import Tlsr85


class Tlsr85Keyboard(Tlsr85):


    def __init__(self, base_address, keyboard_address, preamble, packet_size, crc_poly, crc_init, crc_size):
        super().__init__(base_address, crcmod.mkCrcFun(crc_poly, initCrc=crc_init, rev=False, xorOut=0x0000))
        self.keyboard_address = keyboard_address
        self.full_address = base_address + ":" + keyboard_address
        self.preamble = preamble
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
                chars += Tlsr85KeyboardScancode.SCANCODE_TO_CHAR.value.get((int(scancode), modifier), "")
            return chars
        return Tlsr85KeyboardScancode.SCANCODE_TO_CHAR.value.get((int(array[0], 16), modifier), "")


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
    

    def build_array(self, scancodes):
        array = b""
        for i in range(len(scancodes)):
            if i == 6 :
                break
            if scancodes[i] in Tlsr85KeyboardScancode:
                array += scancodes[i].value.to_bytes(1, "big")
        array += unhexlify("00" * (6 - len(scancodes)))
        return array
    
    

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
    MODIFIER_KEY_PRESSED    = 1 << 8
    MODIFIER_MULTIPLE_KEY   = 1 << 9



class Tlsr85KeyboardScancode(Enum):
    KEY_NONE                = 0x00
    KEY_A                   = 0x14
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
    KEY_Q                   = 0x04
    KEY_R                   = 0x15
    KEY_S                   = 0x16
    KEY_T                   = 0x17
    KEY_U                   = 0x18
    KEY_V                   = 0x19
    KEY_W                   = 0x1D
    KEY_X                   = 0x1B
    KEY_Y                   = 0x1C
    KEY_Z                   = 0x1A
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
    KEY_COMMA               = 0x10
    KEY_ENTER               = 0x28
    KEY_ESCAPE              = 0x29
    KEY_BACKSPACE           = 0x2A
    KEY_TAB                 = 0x2B
    KEY_SPACE               = 0x2C
    KEY_BRACKET_RIGHT       = 0x2D
    KEY_MINUS               = 0x2E
    KEY_CARET               = 0x2F
    KEY_DOLLAR              = 0x30
    KEY_MICRO               = 0x31
    KEY_U_GRAVE             = 0x34
    KEY_SQUARED             = 0x35
    KEY_SEMICOLON           = 0x36
    KEY_COLON               = 0x37
    KEY_EQUAL               = 0x38
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
    KEY_KEYPAD_POINT        = 0x63
    KEY_MENU                = 0x65
    KEY_MUSIC               = 0xAA
    KEY_STOP                = 0xB1
    KEY_BEFORE              = 0xAF
    KEY_AFTER               = 0xAE
    KEY_VOLUME_DOWN         = 0xB4
    KEY_VOLUME_UP           = 0xB3
    KEY_MUTE                = 0xB2
    KEY_MENU_REFRESH        = 0xA4
    KEY_SEARCH              = 0xA3
    KEY_PARAMETER           = 0xC
    KEY_LOCK                = 0xF
    KEY_FULLSCREEN          = 0xAC

    # TODO add <
    SCANCODE_TO_CHAR = {
        (KEY_A, 0) : "a",
        (KEY_B, 0) : "b",
        (KEY_C, 0) : "c",
        (KEY_D, 0) : "d",
        (KEY_E, 0) : "e",
        (KEY_F, 0) : "f",
        (KEY_G, 0) : "g",
        (KEY_H, 0) : "h",
        (KEY_I, 0) : "i",
        (KEY_J, 0) : "j",
        (KEY_K, 0) : "k",
        (KEY_L, 0) : "l",
        (KEY_M, 0) : "m",
        (KEY_N, 0) : "n",
        (KEY_O, 0) : "o",
        (KEY_P, 0) : "p",
        (KEY_Q, 0) : "q",
        (KEY_R, 0) : "r",
        (KEY_S, 0) : "s",
        (KEY_T, 0) : "t",
        (KEY_U, 0) : "u",
        (KEY_V, 0) : "v",
        (KEY_W, 0) : "w",
        (KEY_X, 0) : "x",
        (KEY_Y, 0) : "y",
        (KEY_Z, 0) : "z",
        (KEY_1, 0) : "&",
        (KEY_2, 0) : "é",
        (KEY_3, 0) : "\"",
        (KEY_4, 0) : "\'",
        (KEY_5, 0) : "(",
        (KEY_6, 0) : "§",
        (KEY_7, 0) : "è",
        (KEY_8, 0) : "!",
        (KEY_9, 0) : "ç",
        (KEY_0, 0) : "à",
        (KEY_BRACKET_RIGHT, 0) : ")",
        (KEY_MINUS, 0) : "-",
        (KEY_SQUARED, 0) : "²",
        (KEY_CARET, 0) : "^",
        (KEY_DOLLAR, 0) : "$",
        (KEY_U_GRAVE, 0) : "ù",
        (KEY_MICRO, 0) : "µ",
        (KEY_COMMA, 0) : ",",
        (KEY_SEMICOLON, 0) : ";",
        (KEY_COLON, 0) : ":",
        (KEY_EQUAL, 0) : "=",
        (KEY_KEYPAD_1, 0) : "1",
        (KEY_KEYPAD_2, 0) : "2",
        (KEY_KEYPAD_3, 0) : "3",
        (KEY_KEYPAD_4, 0) : "4",
        (KEY_KEYPAD_5, 0) : "5",
        (KEY_KEYPAD_6, 0) : "6",
        (KEY_KEYPAD_7, 0) : "7",
        (KEY_KEYPAD_8, 0) : "8",
        (KEY_KEYPAD_9, 0) : "9",
        (KEY_KEYPAD_0, 0) : "0",
        (KEY_KEYPAD_DIVIDE, 0) : "/",
        (KEY_KEYPAD_MULTIPLY, 0) : "*",
        (KEY_KEYPAD_SUBTRACT, 0) : "-",
        (KEY_KEYPAD_ADD, 0) : "+",
        (KEY_KEYPAD_POINT, 0) : ".",

        (KEY_A, 1) : "A",
        (KEY_B, 1) : "B",
        (KEY_C, 1) : "C",
        (KEY_D, 1) : "D",
        (KEY_E, 1) : "E",
        (KEY_F, 1) : "F",
        (KEY_G, 1) : "G",
        (KEY_H, 1) : "H",
        (KEY_I, 1) : "I",
        (KEY_J, 1) : "J",
        (KEY_K, 1) : "K",
        (KEY_L, 1) : "L",
        (KEY_M, 1) : "M",
        (KEY_N, 1) : "N",
        (KEY_O, 1) : "O",
        (KEY_P, 1) : "P",
        (KEY_Q, 1) : "Q",
        (KEY_R, 1) : "R",
        (KEY_S, 1) : "S",
        (KEY_T, 1) : "T",
        (KEY_U, 1) : "U",
        (KEY_V, 1) : "V",
        (KEY_W, 1) : "W",
        (KEY_X, 1) : "X",
        (KEY_Y, 1) : "Y",
        (KEY_Z, 1) : "Z",
        (KEY_1, 1) : "1",
        (KEY_2, 1) : "2",
        (KEY_3, 1) : "3",
        (KEY_4, 1) : "4",
        (KEY_5, 1) : "5",
        (KEY_6, 1) : "6",
        (KEY_7, 1) : "7",
        (KEY_8, 1) : "8",
        (KEY_9, 1) : "9",
        (KEY_0, 1) : "0",
        (KEY_BRACKET_RIGHT, 1) : "°",
        (KEY_MINUS, 1) : "_",
        (KEY_SQUARED, 1) : "³",
        (KEY_CARET, 1) : "¨",
        (KEY_DOLLAR, 1) : "*",
        (KEY_U_GRAVE, 1) : "%",
        (KEY_MICRO, 1) : "£",
        (KEY_COMMA, 1) : "?",
        (KEY_SEMICOLON, 1) : ".",
        (KEY_COLON, 1) : "/",
        (KEY_EQUAL, 1) : "+",
        (KEY_KEYPAD_DIVIDE, 1) : "/",
        (KEY_KEYPAD_MULTIPLY, 1) : "*",
        (KEY_KEYPAD_SUBTRACT, 1) : "-",
        (KEY_KEYPAD_ADD, 1) : "+",

        (KEY_A, 2) : "@",
        (KEY_B, 2) : "“",
        (KEY_C, 2) : "¢",
        (KEY_D, 2) : "ð",
        (KEY_E, 2) : "€",
        (KEY_F, 2) : "đ",
        (KEY_G, 2) : "ŋ",
        (KEY_H, 2) : "ħ",
        (KEY_I, 2) : "→",
        (KEY_J, 2) : "ˀ",
        (KEY_K, 2) : "ĸ",
        (KEY_L, 2) : "ł",
        (KEY_M, 2) : "´",
        (KEY_N, 2) : "”",
        (KEY_O, 2) : "œ",
        (KEY_P, 2) : "þ",
        (KEY_Q, 2) : "æ",
        (KEY_R, 2) : "¶",
        (KEY_S, 2) : "ß",
        (KEY_T, 2) : "ŧ",
        (KEY_U, 2) : "↓",
        (KEY_V, 2) : "„",
        (KEY_W, 2) : "«",
        (KEY_X, 2) : "»",
        (KEY_Y, 2) : "←",
        (KEY_Z, 2) : "ſ",
        (KEY_1, 2) : "|",
        (KEY_2, 2) : "@",
        (KEY_3, 2) : "#",
        (KEY_4, 2) : "¼",
        (KEY_5, 2) : "½",
        (KEY_6, 2) : "^",
        (KEY_7, 2) : "{",
        (KEY_8, 2) : "[",
        (KEY_9, 2) : "{",
        (KEY_0, 2) : "}",
        (KEY_BRACKET_RIGHT, 2) : "\\",
        (KEY_MINUS, 2) : "¸",
        (KEY_SQUARED, 2) : "¬",
        (KEY_CARET, 2) : "[",
        (KEY_DOLLAR, 2) : "]",
        (KEY_U_GRAVE, 2) : "´",
        (KEY_MICRO, 2) : "`",
        (KEY_COMMA, 2) : "¸",
        (KEY_SEMICOLON, 2) : "•",
        (KEY_COLON, 2) : "·",
        (KEY_EQUAL, 2) : "~",
        (KEY_KEYPAD_1, 2) : "1",
        (KEY_KEYPAD_2, 2) : "2",
        (KEY_KEYPAD_3, 2) : "3",
        (KEY_KEYPAD_4, 2) : "4",
        (KEY_KEYPAD_5, 2) : "5",
        (KEY_KEYPAD_6, 2) : "6",
        (KEY_KEYPAD_7, 2) : "7",
        (KEY_KEYPAD_8, 2) : "8",
        (KEY_KEYPAD_9, 2) : "9",
        (KEY_KEYPAD_0, 2) : "0",
        (KEY_KEYPAD_DIVIDE, 2) : "/",
        (KEY_KEYPAD_MULTIPLY, 2) : "*",
        (KEY_KEYPAD_SUBTRACT, 2) : "-",
        (KEY_KEYPAD_ADD, 2) : "+",
        (KEY_KEYPAD_POINT, 2) : ".",

        (KEY_A, 3) : "Ω",
        (KEY_B, 3) : "‘",
        (KEY_C, 3) : "©",
        (KEY_D, 3) : "Ð",
        (KEY_E, 3) : "¢",
        (KEY_F, 3) : "ª",
        (KEY_G, 3) : "Ŋ",
        (KEY_H, 3) : "Ħ",
        (KEY_I, 3) : "ı",
        (KEY_J, 3) : " ̛",
        (KEY_K, 3) : "&",
        (KEY_L, 3) : "Ł",
        (KEY_M, 3) : "˝",
        (KEY_N, 3) : "’",
        (KEY_O, 3) : "Œ",
        (KEY_P, 3) : "Þ",
        (KEY_Q, 3) : "Æ",
        (KEY_R, 3) : "®",
        (KEY_S, 3) : "ẞ",
        (KEY_T, 3) : "Ŧ",
        (KEY_U, 3) : "↑",
        (KEY_V, 3) : "‚",
        (KEY_W, 3) : "<",
        (KEY_X, 3) : ">",
        (KEY_Y, 3) : "¥",
        (KEY_Z, 3) : "§",
        (KEY_1, 3) : "¡",
        (KEY_2, 3) : "⅛",
        (KEY_3, 3) : "£",
        (KEY_4, 3) : "$",
        (KEY_5, 3) : "⅜",
        (KEY_6, 3) : "⅝",
        (KEY_7, 3) : "⅞",
        (KEY_8, 3) : "™",
        (KEY_9, 3) : "±",
        (KEY_0, 3) : "°",
        (KEY_BRACKET_RIGHT, 3) : "¿",
        (KEY_MINUS, 3) : "˛",
        (KEY_SQUARED, 3) : "˚",
        (KEY_CARET, 3) : "¯",
        (KEY_DOLLAR, 3) : "ˇ",
        (KEY_U_GRAVE, 3) : "˘",
        (KEY_MICRO, 3) : "˘",
        (KEY_COMMA, 3) : "º",
        (KEY_SEMICOLON, 3) : "×",
        (KEY_COLON, 3) : "÷",
        (KEY_EQUAL, 3) : " ̇",
        (KEY_KEYPAD_DIVIDE, 3) : "/",
        (KEY_KEYPAD_MULTIPLY, 3) : "*",
        (KEY_KEYPAD_SUBTRACT, 3) : "-",
        (KEY_KEYPAD_ADD, 3) : "+"
    }
