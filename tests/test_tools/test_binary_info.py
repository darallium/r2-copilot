"""Tests for binary information tools."""

import pytest

from radare2_mcp.models.schemas import SectionInfo, StringInfo, SymbolInfo
from radare2_mcp.tools.binary_info import BinaryInfoTools


@pytest.mark.asyncio
class TestBinaryInfoTools:
    """Test binary information tools functionality."""

    async def test_get_info(self, test_session):
        """Test getting file information."""
        info = await BinaryInfoTools.get_info("test_session")

        assert isinstance(info, dict)
        # Should have basic info
        if info:  # Might be empty for minimal binary
            assert "core" in info or "bin" in info

    async def test_get_sections(self, test_session):
        """Test getting binary sections."""
        sections = await BinaryInfoTools.get_sections("test_session")

        assert isinstance(sections, list)
        for section in sections:
            assert isinstance(section, SectionInfo)
            assert section.name
            assert section.size >= 0
            assert section.vaddr >= 0
            assert section.permissions

    async def test_get_symbols(self, test_session):
        """Test getting symbols."""
        symbols = await BinaryInfoTools.get_symbols("test_session")

        assert isinstance(symbols, list)
        for symbol in symbols:
            assert isinstance(symbol, SymbolInfo)
            assert symbol.name
            assert symbol.offset >= 0
            assert symbol.type

    async def test_get_imports(self, test_session):
        """Test getting imported symbols."""
        symbols = await BinaryInfoTools.get_symbols(imports_only=True, session_id="test_session")

        assert isinstance(symbols, list)
        # Minimal binary might not have imports

    async def test_get_exports(self, test_session):
        """Test getting exported symbols."""
        symbols = await BinaryInfoTools.get_symbols(exports_only=True, session_id="test_session")

        assert isinstance(symbols, list)

    async def test_get_strings_data_section(self, test_session):
        """Test getting strings from data section."""
        strings = await BinaryInfoTools.get_strings(
            data_section_only=True, session_id="test_session"
        )

        assert isinstance(strings, list)
        for string in strings:
            assert isinstance(string, StringInfo)
            assert string.string
            assert string.offset >= 0
            assert string.length > 0

    async def test_get_strings_whole_binary(self, test_session):
        """Test getting strings from whole binary."""
        strings = await BinaryInfoTools.get_strings(
            data_section_only=False, session_id="test_session"
        )

        assert isinstance(strings, list)
        # Whole binary should have at least as many strings as data section

    async def test_get_imports_list(self, test_session):
        """Test getting imports list."""
        imports = await BinaryInfoTools.get_imports("test_session")

        assert isinstance(imports, list)
        for imp in imports:
            assert isinstance(imp, dict)

    async def test_get_exports_list(self, test_session):
        """Test getting exports list."""
        exports = await BinaryInfoTools.get_exports("test_session")

        assert isinstance(exports, list)
        for exp in exports:
            assert isinstance(exp, dict)

    async def test_get_entrypoint(self, test_session):
        """Test getting entrypoint."""
        entry = await BinaryInfoTools.get_entrypoint("test_session")

        if entry is not None:
            assert isinstance(entry, int)
            assert entry > 0

    async def test_get_libraries(self, test_session):
        """Test getting linked libraries."""
        libs = await BinaryInfoTools.get_libraries("test_session")

        assert isinstance(libs, list)
        # Minimal static binary might not have libraries

    async def test_get_relocations(self, test_session):
        """Test getting relocations."""
        relocs = await BinaryInfoTools.get_relocations("test_session")

        assert isinstance(relocs, list)
        for reloc in relocs:
            assert isinstance(reloc, dict)

    async def test_get_headers(self, test_session):
        """Test getting file headers."""
        headers = await BinaryInfoTools.get_headers("test_session")

        assert isinstance(headers, dict)

    async def test_get_binary_info(self, test_session):
        """Test getting comprehensive binary info."""
        info = await BinaryInfoTools.get_binary_info("test_session")

        assert isinstance(info, dict)
        # Check for common fields
        if info:
            possible_fields = ["arch", "bits", "class", "lang", "os", "type"]
            assert any(field in info for field in possible_fields)

    async def test_check_security(self, test_session):
        """Test checking security features."""
        security = await BinaryInfoTools.check_security("test_session")

        assert isinstance(security, dict)
        # Check for security feature flags
        expected_features = ["nx", "pic", "canary", "crypto", "stripped", "static", "relocs"]
        for feature in expected_features:
            assert feature in security
            assert isinstance(security[feature], bool)
