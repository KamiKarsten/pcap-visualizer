from dataclasses import dataclass
from enum import IntEnum

from ..layer import Layer

class IPv4Protocol(IntEnum):
	ICMP = 1
	TCP = 6
	UDP = 17

@dataclass()
class IPv4(Layer):
	source_ip: str
	destination_ip: str
	ttl: int
	protocol: IPv4Protocol
