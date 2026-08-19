from dataclasses import dataclass
from enum import IntEnum

class ICMPv6Type(IntEnum):
	DESTINATION_UNREACHABLE = 1
	ECHO_REQUEST = 128
	ECHO_REPLY = 129

@dataclass
class ICMPv6:
    type: ICMPv6Type
    code: int
