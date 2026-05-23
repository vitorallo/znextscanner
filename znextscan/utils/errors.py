"""Error detection and classification for z/OS command output."""

import re


class RACFPermissionError(PermissionError):
    """Raised when RACF denies access to a command or resource.

    Includes guidance on which RACF authority is needed.
    """

    def __init__(self, message: str, command: str = "", resource: str = "") -> None:
        self.command = command
        self.resource = resource
        super().__init__(message)


# RACF/z/OS error patterns and their meanings
RACF_ERROR_PATTERNS = [
    # ICH408I - insufficient authority (most common)
    (
        re.compile(r"ICH408I\s+(.+?)\s+NOT AUTHORIZED", re.IGNORECASE),
        "Insufficient RACF authority. Grant READ access to IRR.RADMIN.{command_type} "
        "in the FACILITY class: PERMIT IRR.RADMIN.{command_type} CLASS(FACILITY) "
        "ID({userid}) ACCESS(READ)",
    ),
    # ICH409I - resource not found (not an error, just empty result)
    (
        re.compile(r"ICH409I\s+(.+?)\s+NOT FOUND", re.IGNORECASE),
        None,  # Not an error — resource simply doesn't exist
    ),
    # ICH10006I - RACF not active for class
    (
        re.compile(r"ICH10006I\s+(.+?)\s+NOT ACTIVE", re.IGNORECASE),
        "RACF class {match} is not active. Activate with: SETROPTS CLASSACT({match})",
    ),
    # IKJ56702A - TSO command not authorized
    (
        re.compile(r"IKJ56702A\s+COMMAND\s+(.+?)\s+NOT FOUND", re.IGNORECASE),
        "TSO command {match} not available. The command may not be in the TSO "
        "command table or requires different authority.",
    ),
]


def check_racf_errors(output: str, command: str = "", userid: str = "") -> None:
    """Check TSO command output for RACF error messages.

    Raises RACFPermissionError if access was denied.
    Returns silently if no errors found or if error is informational (ICH409I).
    """
    for pattern, guidance_template in RACF_ERROR_PATTERNS:
        match = pattern.search(output)
        if match:
            if guidance_template is None:
                return  # Informational, not an error

            # Extract command type for guidance (LISTUSER, RLIST, etc.)
            command_type = command.split()[0] if command else "UNKNOWN"

            guidance = guidance_template.format(
                command_type=command_type,
                userid=userid or "MRRASCN",
                match=match.group(1).strip(),
            )
            raise RACFPermissionError(
                f"RACF access denied for '{command}': {match.group(0).strip()}. " f"{guidance}",
                command=command,
                resource=match.group(1).strip(),
            )
