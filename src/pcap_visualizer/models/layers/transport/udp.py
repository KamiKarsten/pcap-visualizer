from dataclasses import dataclass

@dataclass()
class UDP():
	source_port: int
	destination_port: int
	length: int