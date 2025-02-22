class DataExporterBase(ABC):
    @abstractmethod
    def export(self, data, filename):
        pass