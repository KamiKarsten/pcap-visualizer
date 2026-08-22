from dataclasses import dataclass
from enum import IntEnum

from ..layer import Layer


class ICMPv6Type(IntEnum):
	DESTINATION_UNREACHABLE = 1
	PACKET_TOO_BIG = 2
	TIME_EXCEEDED = 3
	ECHO_REQUEST = 128
	ECHO_REPLY = 129
	ROUTER_SOLICITATION = 133
	ROUTER_ADVERTISEMENT = 134
	NEIGHBOR_SOLICITATION = 135
	NEIGHBOR_ADVERTISEMENT = 136

@dataclass
class ICMPv6(Layer):
    type: ICMPv6Type
    code: int
