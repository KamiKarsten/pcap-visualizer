from abc import ABC, abstractmethod

from pcap_visualizer.models.information import Information
from pcap_visualizer.models.layer import Layer


class Extractor[T: Information](ABC):
	@abstractmethod
	def extract(self, layer: Layer) -> list[T]:
		raise NotImplementedError # pragma: no cover