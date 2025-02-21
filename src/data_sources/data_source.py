from abc import ABC, abstractmethod

class DataSourceBase(ABC):
    @abstractmethod
    def collect_data(self, search_params):
        pass

    @abstractmethod
    def normalize_data(self, vulnerability):
        pass