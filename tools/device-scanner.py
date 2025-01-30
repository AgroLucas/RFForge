#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
  Wireless Input Device Scanner

  by Matthias Deeg (@matthiasdeeg, matthias.deeg@syss.de)

  based on preso-scanner.py by Marc Newlin (@macrnewlin)

  Scanner for supported 2.4 GHz wireless input devices

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

__version__ = '0.5'
__author__ = 'Marc Newlin, Matthias Deeg'


from lib import common
from protocols import Protocols, HS304


def banner():
    """Show a fancy banner"""

    print("Wireless Input Device Scanner v{0} by Matthias Deeg - SySS GmbH (c) 2019\n"
          "Based on preso-scanner.py by Marc Newlin".format(__version__))


# main program
if __name__ == '__main__':
    # show banner
    banner()

    # Parse command line arguments and initialize the radio
    common.init_args('./device-scanner.py')
    common.parser.add_argument('-p', '--prefix', type=str, help='Promiscuous mode address prefix', default='')
    common.parser.add_argument('-t', '--dwell', type=float, help='Dwell time per channel, in milliseconds', default='100')
    common.parser.add_argument('-d', '--data_rate', type=str, help='Data rate (accepts [250K, 1M, 2M])', default='2M', choices=["250K", "1M", "2M"], metavar='RATE')
    common.parser.add_argument('-f', '--family', required=True, type=Protocols, choices=list(Protocols), help='Protocol family')
    common.parse_and_init()

    # Initialize the target protocol
    if common.args.family is Protocols.HS304:
        p = HS304()
    else:
        raise Exception("Protocol does not support sniffer/scanner: {}"
                        .format(common.args.family))

    # Start device discovery
    p.start_discovery()
    while True:
        pass
