import importlib
import os
from .data_source import DataSourceBase

def load_data_sources(config):
    data_sources = {}
    for file in os.listdir(os.path.dirname(__file__)):
        if file.endswith("_extractor.py"):
            module_name = file[:-3]
            module = importlib.import_module(f".{module_name}", package="data_sources")
            for attr in dir(module):
                cls = getattr(module, attr)
                if isinstance(cls, type) and issubclass(cls, DataSourceBase) and cls is not DataSourceBase:
                    data_sources[module_name.replace('_extractor', '')] = cls()
    return data_sources