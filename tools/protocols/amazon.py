from .protocol import Protocol
from lib import common
from collections import deque
from threading import Thread
import time
import logging


class AmazonBasics(Protocol):
    """AmazonBasics wireless presenter"""

    def __init__(self, address):
        """Constructor"""

        self.address = address

        super(AmazonBasics, self).__init__("AmazonBasics")

    def configure_radio(self):
        """Configure the radio"""

        # Put the radio in sniffer mode
        common.radio.enter_sniffer_mode(self.address)

        # Set the channels to {2..76..1}
        common.channels = range(2, 76, 1)

        # Set the initial channel
        common.radio.set_channel(common.channels[0])

    def send_hid_event(self, scan_code=0, modifiers=0):
        """Send HID event"""

        # Build and enqueue the payload
        payload = ("%02x:00:%02x:00:00:00:00:00:01" % (modifiers, scan_code)).replace(":", "").decode("hex")
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
        timeout = 0.1                       # 100ms

        # Parse the ping payload
        ping_payload = "\x00"

        # Format the ACK timeout and auto retry values
        ack_timeout = 1                     # 500ms
        retries = 4

        # Sweep through the channels and decode ESB packets
        last_ping = time.time()
        channel_index = 0
        address_string = ':'.join("%02X" % ord(c) for c in self.address[::-1])
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
                payload = self.tx_queue.popleft()
                if not common.radio.transmit_payload(payload, ack_timeout, retries):
                    self.tx_queue.appendleft(payload)

    def stop_injection(self):
        """Leave injection mode"""

        while len(self.tx_queue):
            time.sleep(0.001)
            continue
        self.cancel_tx_loop = True
        self.tx_thread.join()
