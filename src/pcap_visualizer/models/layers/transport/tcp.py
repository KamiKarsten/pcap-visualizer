from dataclasses import dataclass
from enum import IntFlag

from ..layer import Layer


class TCPFlags(IntFlag):
	FIN = 1 << 0
	SYN = 1 << 1
	RST = 1 << 2
	PSH = 1 << 3
	ACK = 1 << 4
	URG = 1 << 5
	ECE = 1 << 6
	CWR = 1 << 7
	NS = 1 << 8

@dataclass()
class TCP(Layer):
	source_port: int
	destination_port: int
	sequence_number: int
	acknowledgment_number: int
	flags: TCPFlags
	window: int
