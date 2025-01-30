from enum import Enum


class Protocols(Enum):
    """Supported wireless protocols"""

    HS304 = 'hs304'
    AmazonBasics = 'amazon'
    Canon = 'canon'
    TBBSC = 'tbbsc'
    RII = 'rii'
    Logitech = 'logitech'
    LogitechEncrypted = 'logitech-enc'
    Inateck_WP1001 = 'inateck_wp1001'
    Inateck_WP2002 = 'inateck_wp2002'

    def __str__(self):
        return self.value
