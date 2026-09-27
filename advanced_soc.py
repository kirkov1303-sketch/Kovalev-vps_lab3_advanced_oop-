import re
import time
import functools
from typing import Callable, Any, Optional


def audit_logger(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Декоратор для аудита функций ИБ-анализа.
    Замеряет время выполнения, логирует обнаружение угроз и перехватывает ошибки.
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            if result is True:
                print(f"[AUDIT] Обнаружена угроза: {func.__name__}")
            elif isinstance(result, SecurityEvent):
                print(f"[AUDIT] Обнаружено событие: {result}")
            return result
        except Exception as exc:
            print(f"[AUDIT] Ошибка в {func.__name__}: {exc}")
            return False
        finally:
            elapsed = time.perf_counter() - start_time
            print(f"[AUDIT] {func.__name__}: {elapsed:.6f} сек.")
    return wrapper


class SecurityEvent:
    """
    Класс события безопасности ИБ.
    """
    def __init__(self, timestamp: str, source_ip: str, event_type: str, severity: int = 1) -> None:
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.event_type = event_type
        self.severity = severity

    @property
    def severity(self) -> int:
        return self._severity

    @severity.setter
    def severity(self, value: int) -> None:
        if not 1 <= value <= 5:
            raise ValueError("Severity must be between 1 and 5")
        self._severity = value

    @property
    def is_critical(self) -> bool:
        return self.severity >= 4

    @classmethod
    def from_syslog(cls, raw_line: str) -> "SecurityEvent":
        """
        Фабричный метод: создает объект из строки syslog.
        """
        match = re.match(
            r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
            r"\[(?P<event_type>[^\]]+)\] (?P<message>.*?)(?: from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}))?$",
            raw_line,
        )
        if not match:
            raise ValueError("Invalid syslog format")

        timestamp = match.group("timestamp")
        event_type = match.group("event_type")
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_line)
        if ip_match is None:
            raise ValueError("Source IP not found")
        source_ip = ip_match.group(0)

        message = match.group("message").lower()
        severity = 5 if ("sqli" in message or "attack" in message) else 3
        return cls(timestamp, source_ip, event_type, severity)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        return cls(
            timestamp=data["timestamp"],
            source_ip=data["source_ip"],
            event_type=data["event_type"],
            severity=data.get("severity", 1),
        )

    def __repr__(self) -> str:
        return f"SecurityEvent(ip='{self.source_ip}', type='{self.event_type}', severity={self.severity})"


class IPUtils:
    """
    Класс-утилита для работы с IP-адресами.
    """
    @staticmethod
    def is_private(ip: str) -> bool:
        """
        Проверяет, является ли IP частным (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x).
        """
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            octets = [int(part) for part in parts]
        except ValueError:
            return False
        if any(octet < 0 or octet > 255 for octet in octets):
            return False

        first, second = octets[0], octets[1]
        return (
            first == 10
            or first == 127
            or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168)
        )

    @staticmethod
    def mask_ip(ip: str) -> str:
        """
        Маскирует последний октет IP-адреса.
        Пример: '192.168.1.50' -> '192.168.1.***'
        """
        parts = ip.split(".")
        if len(parts) != 4:
            raise ValueError("Invalid IPv4 address")
        return ".".join(parts[:3] + ["***"])


class BlacklistManager:
    """
    Менеджер заблокированных IP-адресов.
    """
    def __init__(self, initial_ips: Optional[list[str]] = None) -> None:
        self._blocked_ips: set[str] = set(initial_ips) if initial_ips else set()

    def add_ip(self, ip: str) -> None:
        self._blocked_ips.add(ip)

    def remove_ip(self, ip: str) -> None:
        self._blocked_ips.discard(ip)

    def __contains__(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def __len__(self) -> int:
        return len(self._blocked_ips)

    def __repr__(self) -> str:
        return f"BlacklistManager(blocked_count={len(self._blocked_ips)})"
