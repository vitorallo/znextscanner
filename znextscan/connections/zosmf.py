"""z/OSMF REST API connection for z/OS systems.

Implements TSO API (RACF commands) and Console API (MVS display commands).
Tested against z/OS 3.1 on Hercules with z/OSMF V29.

Key design decisions:
- Fresh TSO session per command: avoids prompt-cycling where RACF commands
  get operands split across prompt-response exchanges. Each command gets a
  clean session: start → consume READY → send command → collect output → delete.
- Base64 auth: curl -u breaks with ! in password, so we encode manually.
- Console API: single PUT with immediate response, no session management needed.
- /receive polling: auto-detected — Hercules returns 404, standard z/OSMF uses it.
"""

import base64
import time
from typing import Any

import httpx
import structlog

from znextscan.connections.base import BaseConnection, CommandNotSupportedError
from znextscan.utils.errors import check_racf_errors

log = structlog.get_logger()

# TSO message prefixes to filter from output
TSO_NOISE_PREFIXES = (
    "IKJ56455I",  # logon in progress
    "IKJ56951I",  # no broadcast messages
    "IKJ56703A",  # reenter this operand
    "IKJ56712I",  # invalid keyword
)


class ZOSMFConnection(BaseConnection):
    """z/OSMF REST API connection."""

    def __init__(
        self,
        host: str,
        port: int = 443,
        username: str = "IBMUSER",
        password: str = "",
        verify_ssl: bool = False,
        timeout: int = 60,
        base_path: str = "/zosmf",
    ) -> None:
        self.base_url = f"https://{host}:{port}{base_path}"
        self.timeout = timeout

        auth_bytes = f"{username}:{password}".encode()
        auth_b64 = base64.b64encode(auth_bytes).decode()

        self.headers = {
            "Authorization": f"Basic {auth_b64}",
            "X-CSRF-ZOSMF-HEADER": "*",
        }

        self.client = httpx.Client(
            base_url=self.base_url,
            headers=self.headers,
            verify=verify_ssl,
            timeout=float(timeout),
        )

        self._receive_unsupported: bool = False

    # ---- TSO session helpers ----

    def _tso_start(self) -> str:
        """Start a TSO session. Returns servlet key."""
        resp = self.client.post(
            "/tsoApp/tso",
            params={
                "proc": "IZUFPROC",
                "chset": "697",
                "cpage": "1047",
                "rows": "204",
                "cols": "160",
                "acct": "IZUACCT",
                "rsize": "50000",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        key = data.get("servletKey")
        if not key:
            raise ConnectionError(f"Failed to start TSO session: {data}")
        return key

    def _tso_delete(self, key: str) -> None:
        """Delete a TSO session."""
        try:
            self.client.delete(f"/tsoApp/tso/{key}")
        except Exception:
            pass

    def _tso_send(self, key: str, data_text: str) -> dict[str, Any]:
        """Send data to a TSO session. Returns response JSON."""
        resp = self.client.put(
            f"/tsoApp/tso/{key}",
            json={"TSO RESPONSE": {"VERSION": "0100", "DATA": data_text}},
            headers={**self.headers, "Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()

    def _tso_receive(self, key: str) -> dict[str, Any] | None:
        """Poll for pending TSO output. Returns None if unavailable."""
        if self._receive_unsupported:
            return None
        resp = self.client.get(f"/tsoApp/tso/{key}/receive")
        if resp.status_code == 404:
            self._receive_unsupported = True
            return None
        if not resp.content:
            return None
        try:
            return resp.json()
        except Exception:
            return None

    @staticmethod
    def _extract_lines(data: dict[str, Any]) -> list[str]:
        """Extract message text lines from TSO response JSON."""
        return [
            item["TSO MESSAGE"]["DATA"] for item in data.get("tsoData", []) if "TSO MESSAGE" in item
        ]

    @staticmethod
    def _has_prompt(data: dict[str, Any]) -> bool:
        """Check if response contains a TSO PROMPT."""
        return any("TSO PROMPT" in item for item in data.get("tsoData", []))

    @staticmethod
    def _filter_output(lines: list[str]) -> str:
        """Filter TSO noise and READY lines, return clean output."""
        result = [
            line
            for line in lines
            if line.strip() not in ("READY", "")
            and not any(line.strip().startswith(p) for p in TSO_NOISE_PREFIXES)
        ]
        return "\n".join(result)

    # ---- TSO command execution ----

    def execute_tso_command(self, command: str) -> str:
        """Execute a TSO/RACF command using a fresh session.

        Each command gets its own TSO session to avoid prompt-cycling issues
        where RACF command operands get split across prompt-response exchanges.

        On Hercules z/OSMF, command output may be delivered asynchronously —
        the PUT returns READY but the actual output arrives on a subsequent
        exchange. We handle this by flushing with empty sends after a delay.
        """
        log.debug("tso_command", command=command)

        key = self._tso_start()
        try:
            # Step 1: consume READY prompt from logon
            self._tso_send(key, "")
            time.sleep(0.5)

            # Step 2: send the actual command
            data = self._tso_send(key, command)
            all_lines = self._extract_lines(data)

            # Step 3: collect output
            has_ready = any("READY" in l for l in all_lines)
            has_output = any(
                l.strip() not in ("READY", "")
                and not any(l.strip().startswith(p) for p in TSO_NOISE_PREFIXES)
                for l in all_lines
            )

            if has_ready and has_output:
                # Full output delivered inline — done
                pass
            elif has_ready and not has_output:
                # Got READY but no data yet — Hercules async delivery.
                # Wait and flush to collect buffered output.
                time.sleep(2)
                flush = self._tso_send(key, "")
                all_lines.extend(self._extract_lines(flush))
            else:
                # No READY yet — poll for completion
                self._poll_output(key, all_lines)

        finally:
            self._tso_delete(key)

        output = self._filter_output(all_lines)
        log.debug("tso_output", command=command, output_length=len(output))

        # Check for RACF permission errors in the output
        check_racf_errors(output, command=command)

        return output

    def _poll_output(self, key: str, all_lines: list[str]) -> None:
        """Poll /receive or resend empty to collect remaining output."""
        for _ in range(self.timeout // 2):
            time.sleep(2)
            rd = self._tso_receive(key)
            if rd is None:
                if self._receive_unsupported:
                    # /receive not available — try flushing with empty send
                    flush = self._tso_send(key, "")
                    all_lines.extend(self._extract_lines(flush))
                    return
                continue
            all_lines.extend(self._extract_lines(rd))
            if self._has_prompt(rd) or any("READY" in l for l in self._extract_lines(rd)):
                return

    # ---- Console API ----

    def execute_console_command(self, command: str) -> str:
        """Execute an MVS console command via z/OSMF Console API."""
        log.debug("console_command", command=command)

        try:
            resp = self.client.put(
                "/restconsoles/consoles/defcn",
                json={"cmd": command},
                headers={**self.headers, "Content-Type": "application/json"},
            )
        except httpx.TimeoutException as e:
            raise TimeoutError(
                f"Console command '{command}' timed out after {self.timeout}s"
            ) from e
        except httpx.ConnectError as e:
            raise ConnectionError(f"Cannot connect to z/OSMF: {e}") from e

        if resp.status_code == 404:
            raise CommandNotSupportedError(
                f"Console API not available (HTTP 404) — "
                f"requires z/OSMF V2.3+ for console commands like '{command}'"
            )
        if resp.status_code == 403:
            raise PermissionError(
                f"Not authorized for console command '{command}' — "
                f"user may need OPERCMDS class authority"
            )

        resp.raise_for_status()
        data = resp.json()

        raw_output = data.get("cmd-response", "")
        output = raw_output.replace("\r ", "\n").replace("\r", "\n")

        log.debug("console_output", command=command, output_length=len(output))
        return output

    # ---- USS API ----

    def execute_uss_command(self, command: str) -> str:
        """Execute a USS command. Not yet implemented via z/OSMF."""
        raise CommandNotSupportedError("USS command execution via z/OSMF not yet implemented")

    # ---- Lifecycle ----

    def close(self) -> None:
        """Close HTTP client."""
        self.client.close()

    def test_connection(self) -> dict[str, Any]:
        """Test connectivity by calling /zosmf/info. Returns system info."""
        resp = self.client.get("/info")
        resp.raise_for_status()
        return resp.json()
