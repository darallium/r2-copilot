"""Pytest configuration and fixtures for Radare2 MCP tests."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from radare2_mcp.utils.r2_manager import R2Manager


@pytest.fixture
def r2_manager():
    """Create a fresh R2Manager instance for testing."""
    manager = R2Manager()
    yield manager
    # Cleanup all sessions
    for session_id in list(manager.sessions.keys()):
        manager.close_session(session_id)


@pytest.fixture
def sample_binary():
    """Create a simple test binary."""
    # Create a minimal ELF binary (x86_64)
    # This is a minimal "Hello World" that just exits
    elf_bytes = bytes.fromhex(
        "7f454c46"  # ELF magic
        "02010100"  # 64-bit, little endian, version 1
        "0000000000000000"  # padding
        "02003e00"  # type: EXEC, machine: x86_64
        "01000000"  # version: 1
        "7800400000000000"  # entry point
        "4000000000000000"  # program header offset
        "0000000000000000"  # section header offset
        "00000000"  # flags
        "4000"  # ELF header size
        "3800"  # program header size
        "0100"  # program header count
        "0000"  # section header size
        "0000"  # section header count
        "0000"  # section header string index
        # Program header (PT_LOAD)
        "01000000"  # type: PT_LOAD
        "05000000"  # flags: R+X
        "0000000000000000"  # offset
        "0000400000000000"  # virtual address
        "0000400000000000"  # physical address
        "8000000000000000"  # file size
        "8000000000000000"  # memory size
        "0010000000000000"  # alignment
        # Code (at offset 0x78)
        "b801000000"  # mov eax, 1 (sys_exit)
        "bb00000000"  # mov ebx, 0 (exit code)
        "cd80"  # int 0x80
    )

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(elf_bytes)
        temp_path = f.name

    yield temp_path

    # Cleanup
    try:
        os.unlink(temp_path)
    except:
        pass


@pytest.fixture
def test_c_source():
    """Create a simple C source file for testing."""
    source = """
#include <stdio.h>
#include <string.h>

int vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnerable!
    return 0;
}

void secret_function() {
    printf("Secret password: hunter2\\n");
}

int main(int argc, char *argv[]) {
    printf("Hello, World!\\n");
    
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    
    return 0;
}
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(source)
        temp_path = f.name

    yield temp_path

    # Cleanup
    try:
        os.unlink(temp_path)
    except:
        pass


@pytest.fixture
def compiled_test_binary(test_c_source):
    """Compile the test C source into a binary."""
    import subprocess

    output_file = tempfile.mktemp(suffix=".out")

    try:
        # Try to compile with gcc
        result = subprocess.run(
            ["gcc", "-o", output_file, "-fno-stack-protector", "-no-pie", test_c_source],
            capture_output=True,
        )

        if result.returncode != 0:
            # If compilation fails, return None
            pytest.skip("GCC not available or compilation failed")
            return None

        yield output_file

    finally:
        # Cleanup
        try:
            if os.path.exists(output_file):
                os.unlink(output_file)
        except:
            pass


@pytest.fixture
async def test_session(r2_manager, sample_binary):
    """Create a test session with a sample binary."""
    session = r2_manager.create_session(
        session_id="test_session", file_path=sample_binary, write_mode=False
    )
    yield session
    r2_manager.close_session("test_session")


@pytest.fixture
def mock_data():
    """Provide mock data for testing."""
    return {
        "functions": [
            {"name": "main", "offset": 0x401000, "size": 100},
            {"name": "func1", "offset": 0x401100, "size": 50},
            {"name": "func2", "offset": 0x401200, "size": 75},
        ],
        "strings": [
            {"offset": 0x402000, "string": "Hello, World!", "length": 13},
            {"offset": 0x402100, "string": "password123", "length": 11},
            {"offset": 0x402200, "string": "/bin/sh", "length": 7},
        ],
        "sections": [
            {"name": ".text", "vaddr": 0x401000, "size": 0x1000, "permissions": "r-x"},
            {"name": ".data", "vaddr": 0x402000, "size": 0x1000, "permissions": "rw-"},
            {"name": ".bss", "vaddr": 0x403000, "size": 0x1000, "permissions": "rw-"},
        ],
        "gadgets": [
            {"offset": 0x401234, "instructions": ["pop rdi", "ret"]},
            {"offset": 0x401345, "instructions": ["pop rsi", "pop rdx", "ret"]},
            {"offset": 0x401456, "instructions": ["mov rax, rdi", "ret"]},
        ],
    }
