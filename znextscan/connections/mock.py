"""Mock connection that reads from fixture files."""

from pathlib import Path

from znextscan.connections.base import BaseConnection

# Maps command prefix -> fixture filename
FIXTURE_MAP: dict[str, str] = {
    # TSO commands
    "LISTUSER *": "LISTUSER-ALL.txt",
    "SETROPTS LIST": "IAM-002-SETROPTS-LIST.txt",
    "LISTUSER IBMUSER": "IAM-003-LISTUSER-IBMUSER.txt",
    "LISTUSER SYS1": "IAM-003-LISTUSER-IBMUSER.txt",
    "RLIST STARTED * ALL": "IAM-005-STARTED-TASKS.txt",
    "RLIST DATASET SYS1": "SCI-001-APF-PROFILES.txt",
    "RLIST APPL * ALL": "EXT-005-RLIST-APPL.txt",
    "RLIST CONSOLE * ALL": "EXT-006-RLIST-CONSOLE.txt",
    "NETSTAT CONN": "EXT-001-NETSTAT-CONN.txt",
    "LISTDS": "EXT-013-LISTDS-LABEL.txt",
    "RLIST MFADEF": "MYT-C10-MFADEF.txt",
    "RLIST EJBROLE": "MYT-R10-EJBROLE.txt",
    # Mythos-native scriptable checks
    "LISTA STATUS": "MYT-R01-LISTALC.txt",
    "$D PROCLIB": "MYT-R01-PROCLIB.txt",
    "D IPLINFO": "MYT-V01-IPLINFO.txt",
    # MYT-X01 reuses the SMS storage-group display ("D SMS,SG" -> EXT-BCK-SMS-SG.txt)
    # Console commands
    "D PROG,APF": "ID-003-APF-LIST.txt",
    "D SMF,O": "MON-001-SMF-STATUS.txt",
    "D ICSF,CARDS": "ENC-005-ICSF-CARDS.txt",
    "D ICSF": "ENC-002-ICSF-LIST.txt",
    "D TCPIP": "EXT-014-TCPIP-CONN.txt",
    "D SMS,SG": "EXT-BCK-SMS-SG.txt",
    "D A,L": "EXT-BCK-DA.txt",
}

# USS commands map
USS_FIXTURE_MAP: dict[str, str] = {
    "java -version": "EXT-002-JAVA-VERSION.txt",
    "cat /etc/syslog.conf": "EXT-003-SYSLOG-CONF.txt",
    "netstat -a": "EXT-011-NETSTAT-USS.txt",
    "ps -ef": "EXT-012-PS-EF.txt",
    "ssh -V": "MYT-V07-USSPKG.txt",
    "command -v java": "MYT-V02-JRES.txt",
    'echo "@@WW@@"': "MYT-C12-PERMS.txt",
}


class MockConnection(BaseConnection):
    """Connection that reads responses from fixture files."""

    def __init__(self, fixture_dir: str | Path) -> None:
        self.fixture_dir = Path(fixture_dir)
        if not self.fixture_dir.is_dir():
            raise FileNotFoundError(f"Fixture directory not found: {self.fixture_dir}")

    def _resolve_fixture(self, command: str, mapping: dict[str, str]) -> str:
        """Find and read the fixture file for a given command."""
        cmd_clean = command.strip()
        # Try exact match first, then prefix match
        for pattern, filename in mapping.items():
            if cmd_clean.upper().startswith(pattern.upper()):
                fixture_path = self.fixture_dir / filename
                if fixture_path.exists():
                    return fixture_path.read_text()
                raise FileNotFoundError(f"Fixture file not found: {fixture_path}")

        raise ValueError(f"No fixture mapping for command: {command}")

    def execute_tso_command(self, command: str) -> str:
        return self._resolve_fixture(command, FIXTURE_MAP)

    def execute_console_command(self, command: str) -> str:
        return self._resolve_fixture(command, FIXTURE_MAP)

    def execute_uss_command(self, command: str) -> str:
        return self._resolve_fixture(command, USS_FIXTURE_MAP)

    def close(self) -> None:
        pass
