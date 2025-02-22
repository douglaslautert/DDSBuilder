import os
import importlib
from .data_exporter import DataExporterBase

def load_exporters(config, filename):
    exporters = {}
    for file in os.listdir(os.path.dirname(__file__)):
        if file.endswith("_exporter.py"):
            module_name = file[:-3]
            module = importlib.import_module(f".{module_name}", package="output")
            for attr in dir(module):
                cls = getattr(module, attr)
                if isinstance(cls, type) and issubclass(cls, DataExporterBase) and cls is not DataExporterBase:
                    exporters[module_name.replace('_exporter', '')] = cls(filename)
    return exporters