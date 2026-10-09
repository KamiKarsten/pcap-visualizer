from abc import ABC, abstractmethod
from typing import TypeVar

from pcap_visualizer.models.information import Information
from pcap_visualizer.models.layer import Layer

T = TypeVar("T", bound=Information)

class Extractor[T: Information](ABC):
	@abstractmethod
	def extract(self, layer: Layer) -> list[T]:
		raise NotImplementedError # pragma: no cover