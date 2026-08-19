from dataclasses import dataclass

@dataclass()
class IPv6:
	source_ip: str
	destination_ip: str
	hop_limit: int
	next_header: int