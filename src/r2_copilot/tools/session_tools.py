"""Session management tools for Radare2 MCP server."""

import uuid
from typing import List, Optional

from r2_copilot.models.schemas import R2Session
from r2_copilot.server.instance import mcp
from r2_copilot.utils.r2_manager import r2_manager


@mcp.tool()
async def create_session(
    file_path: Optional[str] = None,
    pid: Optional[int] = None,
    write_mode: bool = False,
    debug_mode: bool = False,
    session_name: Optional[str] = None,
) -> R2Session:
    """
    Create a new Radare2 session.

    Args:
        file_path: Path to binary file to analyze
        pid: Process ID to attach to
        write_mode: Enable write mode
        debug_mode: Enable debugger mode
        session_name: Optional session name (auto-generated if not provided)

    Returns:
        Session information
    """
    session_id = session_name or str(uuid.uuid4())[:8]

    session = r2_manager.create_session(
        session_id=session_id,
        file_path=file_path,
        pid=pid,
        write_mode=write_mode,
        debug_mode=debug_mode,
    )

    return session


@mcp.tool()
async def list_sessions() -> List[R2Session]:
    """List all active Radare2 sessions."""
    return r2_manager.list_sessions()


@mcp.tool()
async def close_session(session_id: str) -> bool:
    """Close a Radare2 session."""
    return r2_manager.close_session(session_id)


@mcp.tool()
async def switch_session(session_id: str) -> bool:
    """Switch to a different session."""
    return r2_manager.switch_session(session_id)
