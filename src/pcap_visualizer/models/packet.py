from dataclasses import dataclass

from .protocols import Protocol

@dataclass
class PacketInfo:
	source_ip: str | None
	source_port: int | None
	source_mac: str | None
	destination_ip: str | None
	destination_port: int | None
	destination_mac: str | None
	protocol: Protocol
	size: int

	def __str__(self):
		source = self.source_ip or self.source_mac or "unknown"
		destination = self.destination_ip or self.destination_mac or "unknown"

		if self.source_ip and ":" in self.source_ip:
			source = f"[{source}]"

		if self.destination_ip and ":" in self.destination_ip:
			destination = f"[{destination}]"

		if self.source_port is not None:
			source += f":{self.source_port}"

		if self.destination_port is not None:
			destination += f":{self.destination_port}"

		return (
			f"{source} -> {destination} "
			f"[{self.protocol.value}] "
			f"{self.size} bytes"
		)