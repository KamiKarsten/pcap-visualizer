from dataclasses import dataclass
from enum import IntEnum

from ..layer import Layer


class ICMPType(IntEnum):
	DESTINATION_UNREACHABLE = 3
	ECHO_REQUEST = 8
	ECHO_REPLY = 0

@dataclass
class ICMP(Layer):
	type: ICMPType
	code: int
