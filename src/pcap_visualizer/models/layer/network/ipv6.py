from dataclasses import dataclass
from enum import IntEnum

from pcap_visualizer.models.layer.layer import Layer


class IPv6NextHeader(IntEnum):
	TCP = 6
	UDP = 17
	ICMPv6 = 58

@dataclass()
class IPv6(Layer):
	source_ip: str
	destination_ip: str
	hop_limit: int
	next_header: IPv6NextHeader