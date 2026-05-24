"""MCP server instance for Radare2."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "Radare2 MCP Server",
    dependencies=["r2pipe"],
    instructions=(
        "This server provides tools to analyze binary files using radare2. "
        "Start by using 'create_session' to open a binary file for analysis."
    ),
)
