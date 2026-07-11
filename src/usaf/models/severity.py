from enum import Enum, auto


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> float:
        mapping: dict[Severity, float] = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0,
        }
        return mapping[self]

    @property
    def level(self) -> int:
        mapping: dict[Severity, int] = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return mapping[self]

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score >= 1.0:
            return cls.LOW
        return cls.INFO

    def __lt__(self, other: "Severity") -> bool:
        return self.level < other.level

    def __le__(self, other: "Severity") -> bool:
        return self.level <= other.level

    def __gt__(self, other: "Severity") -> bool:
        return self.level > other.level

    def __ge__(self, other: "Severity") -> bool:
        return self.level >= other.level


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def multiplier(self) -> float:
        mapping: dict[Confidence, float] = {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.7,
            Confidence.LOW: 0.4,
        }
        return mapping[self]

    @property
    def level(self) -> int:
        mapping: dict[Confidence, int] = {
            Confidence.HIGH: 3,
            Confidence.MEDIUM: 2,
            Confidence.LOW: 1,
        }
        return mapping[self]


class CheckCategory(str, Enum):
    SYSTEM = "SYSTEM"
    NETWORK = "NETWORK"
    USERS = "USERS"
    PERMISSIONS = "PERMISSIONS"
    SERVICES = "SERVICES"
    PACKAGES = "PACKAGES"
    KERNEL = "KERNEL"
    SECURITY = "SECURITY"
    PERSISTENCE = "PERSISTENCE"
    CONTAINERS = "CONTAINERS"
    COMPLIANCE = "COMPLIANCE"
    COMPROMISE = "COMPROMISE"
    FORENSICS = "FORENSICS"
    BOOT = "BOOT"
    AUDIT = "AUDIT"
    AUTHENTICATION = "AUTHENTICATION"
    PROCESSES = "PROCESSES"
    FILESYSTEM = "FILESYSTEM"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    GENERAL = "GENERAL"
