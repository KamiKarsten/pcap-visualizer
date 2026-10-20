from dataclasses import dataclass
from enum import IntFlag

from pcap_visualizer.models.layer.layer import Layer


class TCPFlags(IntFlag):
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
	ECE = 0x40
	CWR = 0x80
	NS =  0x100

@dataclass()
class TCP(Layer):
	source_port: int
	destination_port: int
	sequence_number: int
	acknowledgment_number: int
	flags: TCPFlags
	window: int
