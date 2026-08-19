from dataclasses import dataclass
from enum import IntEnum

class EthernetType(IntEnum):
	IPV4 = 0x800
	ARP = 0x806
	IPV6 = 0x80DD

@dataclass()
class Ethernet:
	source_mac: str
	destination_mac: str
	ether_type: EthernetType

