class USAFError(Exception):
    """Base exception for all USAF errors."""


class PluginError(USAFError):
    """Raised when a plugin encounters an error."""


class PluginRegistrationError(PluginError):
    """Raised when plugin registration fails."""


class PluginNotFoundError(PluginError):
    """Raised when a requested plugin is not found."""


class PluginDependencyError(PluginError):
    """Raised when plugin dependencies cannot be satisfied."""


class CollectorError(USAFError):
    """Raised when a collector encounters an error."""


class CollectorTimeoutError(CollectorError):
    """Raised when a collector times out."""


class ConfigurationError(USAFError):
    """Raised when configuration is invalid."""


class ReportError(USAFError):
    """Raised when report generation fails."""


class ScoringError(USAFError):
    """Raised when scoring encounters an error."""


class CacheError(USAFError):
    """Raised when cache operations fail."""


class ParseError(USAFError):
    """Raised when parsing fails."""


class BaselineError(USAFError):
    """Raised when baseline comparison fails."""


class PolicyError(USAFError):
    """Raised when policy loading fails."""
