import importlib
import os
from .normalizer import NormalizerBase

def load_normalizers(config):
    normalizers = {}
    for file in os.listdir(os.path.dirname(__file__)):
        if file.endswith("_normalizer.py"):
            module_name = file[:-3]
            module = importlib.import_module(f".{module_name}", package="processing")
            for attr in dir(module):
                cls = getattr(module, attr)
                if isinstance(cls, type) and issubclass(cls, NormalizerBase) and cls is not NormalizerBase:
                    normalizers[module_name.replace('_normalizer', '')] = cls()
    return normalizers