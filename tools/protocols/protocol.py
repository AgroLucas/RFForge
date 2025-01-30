from threading import Thread
from enum import Enum
from lib import common


class Protocol(object):
    """Protocol"""

    # USB HID keyboard modifier
    MODIFIER_NONE           = 0
    MODIFIER_CONTROL_LEFT   = 1 << 0
    MODIFIER_SHIFT_LEFT     = 1 << 1
    MODIFIER_ALT_LEFT       = 1 << 2
    MODIFIER_GUI_LEFT       = 1 << 3
    MODIFIER_CONTROL_RIGHT  = 1 << 4
    MODIFIER_SHIFT_RIGHT    = 1 << 5
    MODIFIER_ALT_RIGHT      = 1 << 6
    MODIFIER_GUI_RIGHT      = 1 << 7

    def __init__(self, name):
        """Constructor"""
        self.name = name
        self.cancel = False
        self.configure_radio()

    def start_discovery(self):
        """Start device discovery loop"""
        self.thread = Thread(target=self.discovery_loop, args=(self.cancel,))
        self.thread.daemon = True
        self.thread.start()

    def stop_discovery(self):
        """Stop device discovery loop"""
        self.cancel = True
        self.thread.join()

    def configure_radio(self):
        """Configure the radio"""
        raise NotImplementedError()

    def discovery_loop(self, cancel):
        """Discovery loop"""
        raise NotImplementedError()

    def send_hid_event(self, scan_code, shift, ctrl, win):
        """Send a HID event"""
        raise NotImplementedError()

    def start_injection(self):
        """Enter injection mode"""
        raise NotImplementedError()

    def stop_injection(self):
        """Leave injection mode"""
        raise NotImplementedError()
