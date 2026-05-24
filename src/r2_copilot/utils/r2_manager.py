"""Radare2 session management using r2pipe."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import r2pipe

from r2_copilot.models.schemas import Architecture, R2Session

logger = logging.getLogger(__name__)


class R2Manager:
    """Manages Radare2 sessions through r2pipe."""

    _instance = None

    def __new__(cls):
        """Singleton pattern to ensure single instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.sessions: Dict[str, r2pipe.open_sync.open] = {}
        self.session_info: Dict[str, R2Session] = {}
        self.current_session: Optional[str] = None
        self._initialized = True

    def create_session(
        self,
        session_id: str,
        file_path: Optional[str] = None,
        pid: Optional[int] = None,
        write_mode: bool = False,
        debug_mode: bool = False,
        options: Optional[List[str]] = None,
    ) -> R2Session:
        """Create a new Radare2 session."""
        try:
            flags = []
            if write_mode:
                flags.append("-w")
            if debug_mode:
                flags.append("-d")
            if options:
                flags.extend(options)

            if pid:
                # Attach to process
                target = f"pid://{pid}"
                r2 = r2pipe.open(target, flags=flags)
            elif file_path:
                # Open file
                if not Path(file_path).exists():
                    raise FileNotFoundError(f"File not found: {file_path}")
                r2 = r2pipe.open(file_path, flags=flags)
            else:
                # Open empty session with malloc
                r2 = r2pipe.open("malloc://512", flags=flags)

            self.sessions[session_id] = r2

            # Get session info
            info = json.loads(r2.cmd("ij"))

            session = R2Session(
                session_id=session_id,
                file_path=file_path,
                pid=pid,
                architecture=self._parse_arch(info.get("bin", {}).get("arch")),
                bits=info.get("bin", {}).get("bits"),
                endian=info.get("bin", {}).get("endian"),
                is_debugger=debug_mode,
                write_mode=write_mode,
            )

            self.session_info[session_id] = session
            self.current_session = session_id

            logger.info(f"Created session {session_id}")
            return session

        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise

    def get_session(self, session_id: Optional[str] = None) -> r2pipe.open_sync.open:
        """Get a Radare2 session."""
        if session_id is None:
            session_id = self.current_session

        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")

        return self.sessions[session_id]

    def close_session(self, session_id: str) -> bool:
        """Close a Radare2 session."""
        if session_id in self.sessions:
            try:
                self.sessions[session_id].quit()
                del self.sessions[session_id]
                del self.session_info[session_id]

                if self.current_session == session_id:
                    self.current_session = None
                    if self.sessions:
                        self.current_session = list(self.sessions.keys())[0]

                logger.info(f"Closed session {session_id}")
                return True
            except Exception as e:
                logger.error(f"Failed to close session: {e}")
                return False
        return False

    def execute_command(
        self, command: str, session_id: Optional[str] = None, json_output: bool = False
    ) -> Any:
        """Execute a Radare2 command."""
        r2 = self.get_session(session_id)

        try:
            if json_output and not command.endswith("j"):
                # Many r2 commands support JSON output with 'j' suffix
                result = r2.cmdj(command + "j")
            elif json_output:
                result = r2.cmdj(command)
            else:
                result = r2.cmd(command)

            return result
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise

    def execute_batch(self, commands: List[str], session_id: Optional[str] = None) -> List[Any]:
        """Execute multiple commands in sequence."""
        results = []
        for cmd in commands:
            result = self.execute_command(cmd, session_id)
            results.append(result)
        return results

    def seek(self, address: Any, session_id: Optional[str] = None) -> int:
        """Seek to an address."""
        r2 = self.get_session(session_id)

        if isinstance(address, str):
            r2.cmd(f"s {address}")
        else:
            r2.cmd(f"s {address:#x}")

        # Return current position
        return int(r2.cmd("s"), 16)

    def get_current_address(self, session_id: Optional[str] = None) -> int:
        """Get current address."""
        r2 = self.get_session(session_id)
        return int(r2.cmd("s"), 16)

    def _parse_arch(self, arch_str: Optional[str]) -> Optional[Architecture]:
        """Parse architecture string to enum."""
        if not arch_str:
            return None

        arch_map = {
            "x86": Architecture.X86,
            "x86_64": Architecture.X86_64,
            "x86.64": Architecture.X86_64,
            "arm": Architecture.ARM,
            "arm64": Architecture.ARM64,
            "mips": Architecture.MIPS,
            "ppc": Architecture.PPC,
            "sparc": Architecture.SPARC,
            "wasm": Architecture.WASM,
        }

        # Normalize the architecture string
        arch_lower = arch_str.lower().replace(" ", "").replace("-", "")

        for key, value in arch_map.items():
            if key.replace(".", "") in arch_lower or arch_lower in key.replace(".", ""):
                return value

        return None

    def list_sessions(self) -> List[R2Session]:
        """List all active sessions."""
        return list(self.session_info.values())

    def switch_session(self, session_id: str) -> bool:
        """Switch current session."""
        if session_id in self.sessions:
            self.current_session = session_id
            return True
        return False


# Global instance
r2_manager = R2Manager()
