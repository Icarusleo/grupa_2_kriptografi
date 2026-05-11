import importlib
import pkgutil
import os
import inspect
from abc import ABC, abstractmethod
from typing import Dict, Type

class HashPlugin(ABC):
    """
    Base class for hash function plugins.
    To add a new hash function, inherit from this class and implement
    the properties and methods.
    """
    
    @property
    @abstractmethod
    def id(self) -> str:
        """Unique identifier for the hash algorithm (e.g., 'sha256')"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Display name for the frontend (e.g., 'SHA-256')"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description of the hash function"""
        pass
        
    @property
    @abstractmethod
    def digest_size(self) -> int:
        """Size of the hash output in bytes"""
        pass

    @abstractmethod
    def compute_hash(self, data: bytes) -> bytes:
        """Computes and returns the hash of the given data"""
        pass

class HashRegistry:
    """Registry to keep track of all available hash plugins"""
    _plugins: Dict[str, HashPlugin] = {}

    @classmethod
    def register(cls, plugin_instance: HashPlugin):
        """Registers a hash plugin instance"""
        if not isinstance(plugin_instance, HashPlugin):
            raise TypeError("Plugin must inherit from HashPlugin")
        cls._plugins[plugin_instance.id] = plugin_instance
        print(f"[OK] Hash Plugin registered: {plugin_instance.name} ({plugin_instance.id})")

    @classmethod
    def get_all(cls) -> Dict[str, HashPlugin]:
        """Returns all registered plugins"""
        return cls._plugins

    @classmethod
    def get(cls, plugin_id: str) -> HashPlugin:
        """Returns a specific plugin by id"""
        return cls._plugins.get(plugin_id)

    @classmethod
    def load_plugins(cls, plugins_dir: str):
        """
        Dynamically loads all modules in the given directory.
        If a module contains a class inheriting from HashPlugin, it instantiates
        and registers it.
        """
        if not os.path.exists(plugins_dir):
            os.makedirs(plugins_dir)
            
        for _, module_name, _ in pkgutil.iter_modules([plugins_dir]):
            module_path = f"hash_plugins.{module_name}"
            module = importlib.import_module(module_path)
            
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                # Check if it's a class and a subclass of HashPlugin, but not the abstract HashPlugin itself
                if inspect.isclass(attr) and issubclass(attr, HashPlugin) and attr is not HashPlugin:
                    # Avoid duplicate instantiations if imported multiple times
                    if attr().id not in cls._plugins:
                        cls.register(attr())
