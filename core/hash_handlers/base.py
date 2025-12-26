from abc import ABC, abstractmethod


class BaseHashHandler(ABC):
    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = []

    @abstractmethod
    def parse_hash_digest_with_metadata(self):
        raise NotImplementedError

    @abstractmethod
    def verify(self, potential_password_match):
        raise NotImplementedError

    @abstractmethod
    def log_parameters(self):
        raise NotImplementedError
