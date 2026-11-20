import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# Regex pour capturer les échecs et succès SSH standards
SSH_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+\S+\s+for\s+(?:invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

@dataclass
class LogEvent:
    timestamp: datetime
    host: str
    status: str
    user: str
    ip: str

def parse_line(line: str, year: int = 2026) -> Optional[LogEvent]:
    match = SSH_LOG_PATTERN.search(line)
    if not match:
        return None
    
    raw_ts = f"{year} {match.group('timestamp')}"
    ts = datetime.strptime(raw_ts, "%Y %b %d %H:%M:%S")
    
    return LogEvent(
        timestamp=ts,
        host=match.group("host"),
        status=match.group("status"),
        user=match.group("user"),
        ip=match.group("ip"),
    )