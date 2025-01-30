#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
  Copyright (C) 2016 Bastille Networks

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

import logging
import time

from binascii import unhexlify
from lib import common

# Parse command line arguments and initialize the radio
common.init_args('./nrf24-scanner.py')
common.parser.add_argument('-p', '--prefix', type=str, help='Promiscuous mode address prefix', default='')
common.parser.add_argument('-d', '--dwell', type=float, help='Dwell time per channel, in milliseconds', default='100')
common.parser.add_argument('-R', '--rate', type=str, help='RF rate', choices=['250K', '1M', '2M'], default='2M')
common.parser.add_argument('-A', '--addrlen', type=int, choices=[2, 3, 4, 5], default=5)
common.parse_and_init()

# Parse the prefix addresses
# prefix_address = common.args.prefix.replace(':', '').decode('hex')
prefix_address = unhexlify(common.args.prefix.replace(':', ''))


if len(prefix_address) > 5:
    raise Exception('Invalid prefix address: {0}'.format(args.address))

# Put the radio in promiscuous mode
rate = common.RF_RATE_2M
if common.args.rate == '1M':
    rate = common.RF_RATE_1M
elif common.args.rate == '250K':
    rate = common.RF_RATE_250K

addrlen = common.args.addrlen
common.radio.enter_promiscuous_mode(prefix_address, rate=rate, addrlen=addrlen)

# Convert dwell time from milliseconds to seconds
dwell_time = common.args.dwell / 1000

# Set the initial channel
common.radio.set_channel(common.channels[0])

# Sweep through the channels and decode ESB packets in pseudo-promiscuous mode
last_tune = time.time()
channel_index = 0
while True:

    # Increment the channel
    if len(common.channels) > 1 and time.time() - last_tune > dwell_time:
        channel_index = (channel_index + 1) % (len(common.channels))
        common.radio.set_channel(common.channels[channel_index])
        last_tune = time.time()

    # Receive payloads
    value = common.radio.receive_payload()
    if len(value) >= addrlen:

        # Split the address and payload
        address, payload = value[0:addrlen], value[addrlen:]

        # Log the packet
        logging.info('{0: >2}  {1: >2}  {2}  {3}'.format(
                common.channels[channel_index],
                len(payload),
                ':'.join('{:02X}'.format(b) for b in address),
                ':'.join('{:02X}'.format(b) for b in payload)))
