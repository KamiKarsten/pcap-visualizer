from dataclasses import dataclass
from enum import IntEnum

from ..layer import Layer


class EthernetType(IntEnum):
	IPV4 = 0x0800
	ARP = 0x0806
	IPV6 = 0x086DD

@dataclass()
class Ethernet(Layer):
	source_mac: str
	destination_mac: str
	ether_type: EthernetType

