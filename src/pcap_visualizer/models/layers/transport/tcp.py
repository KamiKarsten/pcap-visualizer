from dataclasses import dataclass

@dataclass()
class TCP():
	source_port: int
	destination_port: int
	sequence_number: int
	acknowledgment_number: int
	flags: int
	window: int