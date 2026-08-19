from dataclasses import dataclass
from enum import IntEnum

class IPv6NextHeader(IntEnum):
    ICMPv6 = 58
    TCP = 6
    UDP = 17

@dataclass()
class IPv6:
	source_ip: str
	destination_ip: str
	hop_limit: int
	next_header: IPv6NextHeader