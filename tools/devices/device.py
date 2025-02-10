"""
  Copyright (C) 2016 Bastille Networks
  Copyright (C) 2019 Matthias Deeg, SySS GmbH
  Copyright (C) 2025 Lucas Agro

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from abc import ABC, abstractmethod
from binascii import unhexlify
from lib import common
import time


class Device(ABC):
    """Represent a device (keyboard, mouse, ...) that can be sniffed/spoofed using the Crazyradio PA USB dongle.

    Is an abstract class, each device has his own implementation in his corresponding folder.
    """

    def __init__(self, address, address_length, channels, rate, packet_size, preamble, crc_size, crc):
        """ Initialize a device.
        
        Attributes:
            address (str): The address of the device separated by commas (e.g., "55:5A:F2").
            address_length (int): The size in bytes of the address.
            channels (list[int]): A table containing all the channels used by the device (e.g., [34, 47, 68, 75]) (should be even to avoid errors).
            rate (int): The rate of the device. Either 0 for 250Kps, 1 for 1Mbps or 2 for 2Mbps.
            packet_size (int): The size in byte of the packet without the preamble.
            crc_size (int): The size in byte of the CRC.
            crc (Callable[str, str]): The CRC function of the device.
        """
        self.address = address
        self.address_length = address_length
        self.channels = channels
        self.rate = rate
        self.packet_size = packet_size
        self.preamble = preamble
        self.crc_size = crc_size
        self.crc = crc

    

    def check_crc(self, expected_crc, crc_input):
        """Check if the given input produces the expected crc.

        Args:
            expected_crc (str): The expected crc in hexadecimal string.
            crc_input (str): The payload in hexadecimal string that will be inputed to the crc function.
        
        Returns:
            bool: True if the input produces the expected crc, False otherwise.
        """
        return f"{self.crc(unhexlify(crc_input)):04x}" == expected_crc
    

    def calculate_crc(self, crc_input):
        """Calculate the crc from the given input.

        Args:
            crc_input (str): The payload in hexadecimal string that will be inputed to the crc function.

        Returns:
            bytes: The output of the crc function with the given payload in bytes. 
        """
        return self.crc(bytes(crc_input)).to_bytes(2, "big")
    


    @abstractmethod
    def parse_packet(self, packet):
        """Parse a raw packet into a dictionary.

        Args:
            packet (str): The raw packet to parse.

        Returns:
            dict[str, str]: A dictionary of the parsed packet where the keys are strings and the values are hexadecimal strings.  
        """
        pass


    @abstractmethod
    def handle_sniffed_packet(self, packet, channel):
        """Display information about the given packet if it belongs to the correct devices.

        Args:
            packet (dict[str, str]): A dictionary of a parsed packet where the keys are strings and the values are hexadecimal strings.
            channel (int): The channel number from which the packet has been retrieved (e.g. 68 corresponds to 2468 MHz).
        """
        pass


    def sniff(self):
        """Sniff all the device's channels to retrieve raw packet sent in the air. Display information about the retrieved packets.

        Change channel every dwell_time unless we found a packet, in that case the dwell_time is reset.
        """
        dwell_time = 0.2
        channel_index = 0
        #self.channels = range(0,84) # fuzz channels
        common.radio.set_channel(self.channels[channel_index]) # Set channel here to prevent USBError (somehow)
        common.radio.enter_promiscuous_mode_generic(unhexlify(self.address.replace(':', '')), rate=self.rate)
        last_tune = time.time()

        while True:
            # Increment the channel after dwell_time
            if len(self.channels) > 1 and time.time() - last_tune > dwell_time:
                channel_index = (channel_index + 1) % (len(self.channels))
                common.radio.set_channel(self.channels[channel_index])
                last_tune = time.time()

            value = common.radio.receive_payload()
            if len(value) >= self.address_length:
                if bytes(value[:self.address_length]) == unhexlify(self.address.replace(':', '')):    
                    self.handle_sniffed_packet(self.parse_packet(bytes(value)), self.channels[channel_index])
                    last_tune = time.time()
    
    
    def spoof(self, attack):
        """Spoof a device by sending a bunch of signals to the device's dongle.

        Args:
            attack (list[obj]): A table containing the given payload. 
                                The actual signals are present in the table in a raw bytes format. 
                                The table can also contains calls to methods (e.g., time.sleep).
        """
        address = unhexlify(self.address.replace(':', ''))
        preamble = unhexlify(self.preamble.replace(':', ''))
        channel_index = 0
        common.radio.set_channel(self.channels[channel_index]) # Set channel here to prevent USBError (somehow)
        common.radio.enter_promiscuous_mode_generic(address, rate=self.rate)
        for payload in attack:
            if callable(payload):
                payload() # in case we want a delay
            else:
                for i in range(len(self.channels)):
                    common.radio.set_channel(self.channels[i])
                    for _ in range(15):
                        common.radio.transmit_payload_generic(payload=preamble+payload, address=address)
                        time.sleep(0.00001)
