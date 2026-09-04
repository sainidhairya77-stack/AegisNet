"""
Validation utilities
"""

import re
from ipaddress import ip_address, AddressValueError


class IPValidator:
    """IP address validation utilities"""

    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        """Check if string is a valid IPv4 or IPv6 address"""
        try:
            ip_address(ip_str)
            return True
        except (AddressValueError, ValueError):
            return False

    @staticmethod
    def is_valid_ipv4(ip_str: str) -> bool:
        """Check if string is a valid IPv4 address"""
        try:
            ip = ip_address(ip_str)
            return ip.version == 4
        except (AddressValueError, ValueError):
            return False

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if IP is in private range"""
        try:
            ip = ip_address(ip_str)
            return ip.is_private
        except (AddressValueError, ValueError):
            return False

    @staticmethod
    def is_external_ip(ip_str: str) -> bool:
        """Check if IP is external (public)"""
        try:
            ip = ip_address(ip_str)
            return not ip.is_private and not ip.is_loopback and not ip.is_reserved
        except (AddressValueError, ValueError):
            return False


class FileValidator:
    """File validation utilities"""

    @staticmethod
    def is_valid_filename(filename: str, allowed_extensions: list[str]) -> bool:
        """Check if filename has allowed extension"""
        if not filename:
            return False
        
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        return ext in allowed_extensions

    @staticmethod
    def sanitize_filename(filename: str, max_length: int = 255) -> str:
        """
        Sanitize filename to prevent path traversal and other attacks
        Removes dangerous characters and limits length
        """
        # Remove path separators
        filename = filename.replace("\\", "_").replace("/", "_")
        
        # Remove null bytes
        filename = filename.replace("\0", "")
        
        # Keep only safe characters: alphanumeric, dash, underscore, dot
        filename = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
        
        # Remove leading dots
        while filename.startswith("."):
            filename = filename[1:]
        
        # Limit length
        if len(filename) > max_length:
            name, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
            name = name[:max_length - len(ext) - 1]
            filename = f"{name}.{ext}"
        
        return filename


class PortValidator:
    """Port validation utilities"""

    @staticmethod
    def is_valid_port(port: int) -> bool:
        """Check if port is in valid range (1-65535)"""
        return isinstance(port, int) and 1 <= port <= 65535

    @staticmethod
    def is_well_known_port(port: int) -> bool:
        """Check if port is in well-known range (1-1023)"""
        return PortValidator.is_valid_port(port) and port < 1024

    @staticmethod
    def is_registered_port(port: int) -> bool:
        """Check if port is in registered range (1024-49151)"""
        return PortValidator.is_valid_port(port) and 1024 <= port <= 49151

    @staticmethod
    def is_dynamic_port(port: int) -> bool:
        """Check if port is in dynamic/private range (49152-65535)"""
        return PortValidator.is_valid_port(port) and port >= 49152


class ProtocolValidator:
    """Protocol validation utilities"""

    VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "IGMP", "GRE", "IPIP"}

    @staticmethod
    def is_valid_protocol(protocol: str) -> bool:
        """Check if protocol is recognized"""
        return protocol.upper() in ProtocolValidator.VALID_PROTOCOLS


class CIDRValidator:
    """CIDR notation validation"""

    @staticmethod
    def is_valid_cidr(cidr: str) -> bool:
        """Check if string is valid CIDR notation"""
        try:
            parts = cidr.split("/")
            if len(parts) != 2:
                return False
            
            ip = ip_address(parts[0])
            prefix = int(parts[1])
            
            if ip.version == 4 and not (0 <= prefix <= 32):
                return False
            if ip.version == 6 and not (0 <= prefix <= 128):
                return False
            
            return True
        except (AddressValueError, ValueError):
            return False
