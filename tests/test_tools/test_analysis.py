"""Tests for analysis tools."""

import pytest

from radare2_mcp.models.schemas import Address, AnalysisResult, FunctionInfo
from radare2_mcp.tools.analysis import AnalysisTools


@pytest.mark.asyncio
class TestAnalysisTools:
    """Test analysis tools functionality."""

    async def test_analyze_all(self, test_session):
        """Test complete analysis."""
        result = await AnalysisTools.analyze_all("test_session")

        assert isinstance(result, AnalysisResult)
        assert result.success is True
        assert result.message == "Analysis completed successfully"
        assert isinstance(result.functions_found, int)

    async def test_analyze_function_at_current(self, test_session):
        """Test analyzing function at current position."""
        result = await AnalysisTools.analyze_function(session_id="test_session")

        assert isinstance(result, AnalysisResult)
        assert result.success is True

    async def test_analyze_function_at_address(self, test_session):
        """Test analyzing function at specific address."""
        addr = Address(value=0x400078)  # Entry point in our test binary
        result = await AnalysisTools.analyze_function(address=addr, session_id="test_session")

        assert isinstance(result, AnalysisResult)
        assert "0x400078" in result.message or "400078" in result.message

    async def test_list_functions(self, test_session):
        """Test listing functions."""
        # First analyze
        await AnalysisTools.analyze_all("test_session")

        functions = await AnalysisTools.list_functions("test_session")

        assert isinstance(functions, list)
        # Minimal binary might not have many functions
        for func in functions:
            assert isinstance(func, FunctionInfo)
            assert func.name
            assert func.offset >= 0
            assert func.size >= 0

    async def test_get_function_info(self, test_session):
        """Test getting function information."""
        # Analyze first
        await AnalysisTools.analyze_all("test_session")

        info = await AnalysisTools.get_function_info(session_id="test_session")

        if info:  # Might be None if no function at current position
            assert isinstance(info, FunctionInfo)
            assert info.offset >= 0
            assert info.size >= 0

    async def test_rename_function(self, test_session):
        """Test renaming a function."""
        # This test might not work with minimal binary
        # but we test the function call
        result = await AnalysisTools.rename_function(
            old_name="entry0", new_name="my_entry", session_id="test_session"
        )

        assert isinstance(result, bool)

    async def test_analyze_data(self, test_session):
        """Test data analysis."""
        result = await AnalysisTools.analyze_data(session_id="test_session")

        assert isinstance(result, AnalysisResult)
        assert result.success is True

    async def test_get_xrefs_to(self, test_session):
        """Test getting cross references to address."""
        addr = Address(value=0x400078)
        xrefs = await AnalysisTools.get_xrefs_to(address=addr, session_id="test_session")

        assert isinstance(xrefs, list)

    async def test_get_xrefs_from(self, test_session):
        """Test getting cross references from address."""
        addr = Address(value=0x400078)
        xrefs = await AnalysisTools.get_xrefs_from(address=addr, session_id="test_session")

        assert isinstance(xrefs, list)

    async def test_analyze_opcodes(self, test_session):
        """Test analyzing opcodes."""
        opcodes = await AnalysisTools.analyze_opcodes(count=5, session_id="test_session")

        assert isinstance(opcodes, list)
        # Should analyze up to 5 opcodes
        assert len(opcodes) <= 5

    async def test_define_function(self, test_session):
        """Test manually defining a function."""
        addr = Address(value=0x400100)
        result = await AnalysisTools.define_function(
            address=addr, size=50, name="custom_func", session_id="test_session"
        )

        assert isinstance(result, bool)

    async def test_undefine_function(self, test_session):
        """Test removing function metadata."""
        addr = Address(value=0x400078)

        # First define a function
        await AnalysisTools.define_function(address=addr, size=20, session_id="test_session")

        # Then undefine it
        result = await AnalysisTools.undefine_function(address=addr, session_id="test_session")

        assert isinstance(result, bool)

    async def test_address_with_symbol(self, test_session):
        """Test using symbol as address."""
        addr = Address(value="entry0")
        result = await AnalysisTools.analyze_function(address=addr, session_id="test_session")

        assert isinstance(result, AnalysisResult)
