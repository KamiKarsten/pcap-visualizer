from dataclasses import dataclass
from enum import IntEnum

class IPv4Protocol(IntEnum):
	ICMP = 1
	TCP = 6
	UDP = 17

@dataclass()
class IPv4:
	source_ip: str
	destination_ip: str
	ttl: int
	protocol: IPv4Protocol
