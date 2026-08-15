from dataclasses import dataclass

@dataclass
class PacketInfo:
	source: str | None
	destination: str | None
	protocol: str
	source_port: int | None
	destination_port: int | None
	size: int

