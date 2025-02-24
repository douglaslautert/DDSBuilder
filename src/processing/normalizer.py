from abc import ABC, abstractmethod

class NormalizerBase(ABC):
    @abstractmethod
    def normalize_data(self, vulnerability):
        pass


