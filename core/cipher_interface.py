from abc import ABC, abstractmethod

class CipherInterface(ABC):
    """
    Abstract Base Class for VPN Cipher Suites.
    Enforces a standard API for all encryption algorithms to allow hot-swapping.
    """

    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypts the given data using the provided key.
        
        Args:
            data (bytes): The plaintext data to encrypt.
            key (bytes): The secret key.
            
        Returns:
            bytes: The encrypted ciphertext.
        """
        pass

    @abstractmethod
    def decrypt(self, data: bytes, key: bytes) -> bytes:
        """
        Decrypts the given data using the provided key.
        
        Args:
            data (bytes): The ciphertext to decrypt.
            key (bytes): The secret key.
            
        Returns:
            bytes: The decrypted plaintext.
        """
        pass

    @property
    @abstractmethod
    def block_size(self) -> int:
        """Returns the block size of the cipher in bytes."""
        pass
    
    @property
    @abstractmethod
    def key_size(self) -> int:
        """Returns the required key size in bytes."""
        pass
