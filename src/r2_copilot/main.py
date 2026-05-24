# MCPサーバーインスタンスをインポート
from r2_copilot.server.instance import mcp

# 各ツールモジュールをインポートすることで、デコレータが実行され、
# ツールがmcpインスタンスに自動的に登録されます。
from r2_copilot.tools import session_tools  # noqa: F401
from r2_copilot.tools import analysis  # noqa: F401
from r2_copilot.tools import binary_info  # noqa: F401
from r2_copilot.tools import disassembly  # noqa: F401
from r2_copilot.tools import navigation  # noqa: F401
from r2_copilot.tools import search  # noqa: F401
from r2_copilot.tools import write  # noqa: F401
from r2_copilot.tools import debugger  # noqa: F401
from r2_copilot.tools import flags  # noqa: F401
from r2_copilot.tools import config  # noqa: F401

# execute_commandツールを直接登録
from r2_copilot.utils.r2_manager import r2_manager
from typing import Any, Optional


@mcp.tool()
async def execute_command(
    command: str, session_id: Optional[str] = None, json_output: bool = False
) -> Any:
    """
    Execute raw Radare2 command.
    Use this for commands not yet wrapped by specific tools.
    """
    return r2_manager.execute_command(command, session_id, json_output)


def main():
    """MCPサーバーを実行します。"""
    # FastMCP.run()は、コマンドライン引数を解釈してサーバーを起動します。
    mcp.run()


if __name__ == "__main__":
    main()
