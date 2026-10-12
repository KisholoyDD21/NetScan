"""Custom exception hierarchy for NetScan."""


class NetScanError(Exception):
    """Base exception for expected NetScan failures."""


class AuthorizationError(NetScanError):
    """Raised when authorization or scope validation fails."""


class NmapNotFoundError(NetScanError):
    """Raised when the Nmap executable is unavailable."""


class ScanExecutionError(NetScanError):
    """Raised when Nmap fails or times out."""


class TargetValidationError(NetScanError):
    """Raised when a target cannot be safely normalized."""


class ReportError(NetScanError):
    """Raised when report generation fails."""


class ConfigurationError(NetScanError):
    """Raised when configuration is invalid."""
