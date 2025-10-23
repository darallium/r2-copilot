"""Cryptographic algorithm detection tools for Radare2 MCP server."""

import json
import logging
from typing import Any, Dict, List, Optional

from r2_copilot.crypto.constants import (
    AES_SBOX,
    AES_INV_SBOX,
    AES_RCON,
    DES_IP,
    DES_FP,
    SHA1_INITIAL,
    SHA256_INITIAL,
    MD5_INITIAL,
    RSA_COMMON_EXPONENTS,
    BASE64_ALPHABET,
    RC4_IDENTITY_SBOX,
    TEA_DELTA,
    XTEA_DELTA,
    BLOWFISH_P_ARRAY,
    CRC_POLYNOMIALS,
    CRYPTO_CONSTANTS
)
from r2_copilot.models.schemas import (
    CryptoDetection,
    CryptoConstant,
    SearchResult,
)
from r2_copilot.server.instance import mcp
from r2_copilot.utils.r2_manager import r2_manager

logger = logging.getLogger(__name__)


class CryptoDetectionTools:
    """Radare2 cryptographic algorithm detection commands."""

    @staticmethod
    async def detect_aes_sbox(session_id: Optional[str] = None) -> List[CryptoDetection]:
        """
        Detect AES S-Box patterns in the binary.
        Searches for both forward and inverse S-Box tables.
        """
        try:
            detections = []
            
            # Convert S-Box to hex patterns for searching
            sbox_pattern = "".join(f"{x:02x}" for x in AES_SBOX[:16])  # First 16 bytes
            inv_sbox_pattern = "".join(f"{x:02x}" for x in AES_INV_SBOX[:16])  # First 16 bytes
            
            # Search for forward S-Box
            forward_results = r2_manager.execute_command(f"/xj {sbox_pattern}", session_id)
            if isinstance(forward_results, str):
                forward_results = json.loads(forward_results)
            
            for result in forward_results or []:
                # Verify this is actually an S-Box by checking more bytes
                offset = result.get("offset", 0)
                
                # Read 256 bytes from this offset
                hex_data = r2_manager.execute_command(f"px 256 @ {offset:#x}", session_id)
                if hex_data:
                    # Extract hex bytes and compare with full S-Box
                    confidence = await CryptoDetectionTools._calculate_sbox_confidence(
                        hex_data, AES_SBOX
                    )
                    
                    if confidence > 0.8:  # High confidence threshold
                        detections.append(
                            CryptoDetection(
                                algorithm="AES",
                                confidence=confidence,
                                offset=offset,
                                size=256,
                                data=bytes(AES_SBOX),
                                matches=["forward_sbox"],
                                additional_info={
                                    "type": "S-Box (Forward)",
                                    "description": "AES forward substitution box"
                                }
                            )
                        )
            
            # Search for inverse S-Box
            inverse_results = r2_manager.execute_command(f"/xj {inv_sbox_pattern}", session_id)
            if isinstance(inverse_results, str):
                inverse_results = json.loads(inverse_results)
            
            for result in inverse_results or []:
                offset = result.get("offset", 0)
                hex_data = r2_manager.execute_command(f"px 256 @ {offset:#x}", session_id)
                if hex_data:
                    confidence = await CryptoDetectionTools._calculate_sbox_confidence(
                        hex_data, AES_INV_SBOX
                    )
                    
                    if confidence > 0.8:
                        detections.append(
                            CryptoDetection(
                                algorithm="AES",
                                confidence=confidence,
                                offset=offset,
                                size=256,
                                data=bytes(AES_INV_SBOX),
                                matches=["inverse_sbox"],
                                additional_info={
                                    "type": "S-Box (Inverse)",
                                    "description": "AES inverse substitution box"
                                }
                            )
                        )
            
            return detections
            
        except Exception as e:
            logger.error(f"Failed to detect AES S-Box: {e}")
            return []

    @staticmethod
    async def _calculate_sbox_confidence(hex_output: str, expected_sbox: List[int]) -> float:
        """Calculate confidence score for S-Box detection."""
        try:
            # Parse hex output from radare2
            lines = hex_output.strip().split('\n')
            hex_bytes = []
            
            for line in lines:
                # Extract hex bytes from each line (format: "0x00001000  63 7c 77 7b ...")
                if '  ' in line:
                    hex_part = line.split('  ', 1)[1].split('  ')[0]  # Get hex part
                    bytes_in_line = hex_part.split()
                    hex_bytes.extend([int(b, 16) for b in bytes_in_line if len(b) == 2])
            
            if len(hex_bytes) < len(expected_sbox):
                return 0.0
            
            # Compare with expected S-Box
            matches = 0
            for i, expected in enumerate(expected_sbox):
                if i < len(hex_bytes) and hex_bytes[i] == expected:
                    matches += 1
            
            return matches / len(expected_sbox)
            
        except Exception as e:
            logger.error(f"Failed to calculate S-Box confidence: {e}")
            return 0.0

    @staticmethod
    async def detect_crypto_constants(
        algorithm: str, session_id: Optional[str] = None
    ) -> List[CryptoDetection]:
        """
        Detect cryptographic constants for a specific algorithm.
        """
        try:
            detections = []
            
            if algorithm.upper() not in CRYPTO_CONSTANTS:
                return detections
            
            constants = CRYPTO_CONSTANTS[algorithm.upper()]
            
            # Detect based on algorithm type
            if algorithm.upper() == "AES":
                detections.extend(await CryptoDetectionTools.detect_aes_sbox(session_id))
                # Add Round Constants detection
                detections.extend(await CryptoDetectionTools._detect_aes_rcon(session_id))
                # Add Key Schedule detection
                detections.extend(await CryptoDetectionTools.detect_aes_key_schedule(session_id))
                
            elif algorithm.upper() == "DES":
                detections.extend(await CryptoDetectionTools.detect_des_permutation_tables(session_id))
                
            elif algorithm.upper() in ["SHA1", "SHA256", "MD5"]:
                detections.extend(await CryptoDetectionTools._detect_hash_constants(algorithm.upper(), session_id))
                
            elif algorithm.upper() == "RSA":
                detections.extend(await CryptoDetectionTools._detect_rsa_exponents(session_id))
                
            elif algorithm.upper() == "BASE64":
                detections.extend(await CryptoDetectionTools._detect_base64_alphabet(session_id))
            
            return detections
            
        except Exception as e:
            logger.error(f"Failed to detect {algorithm} constants: {e}")
            return []

    @staticmethod
    async def _detect_aes_rcon(session_id: Optional[str] = None) -> List[CryptoDetection]:
        """Detect AES Round Constants."""
        try:
            detections = []
            
            # Search for first few round constants
            rcon_pattern = "".join(f"{x:02x}" for x in AES_RCON[:8])
            
            results = r2_manager.execute_command(f"/xj {rcon_pattern}", session_id)
            if isinstance(results, str):
                results = json.loads(results)
            
            for result in results or []:
                offset = result.get("offset", 0)
                detections.append(
                    CryptoDetection(
                        algorithm="AES",
                        confidence=0.9,
                        offset=offset,
                        size=len(AES_RCON),
                        data=bytes(AES_RCON),
                        matches=["round_constants"],
                        additional_info={
                            "type": "Round Constants",
                            "description": "AES key schedule round constants"
                        }
                    )
                )
            
            return detections
            
        except Exception as e:
            logger.error(f"Failed to detect AES round constants: {e}")
            return []

    @staticmethod
    async def _detect_hash_constants(algorithm: str, session_id: Optional[str] = None) -> List[CryptoDetection]:
        """Detect hash algorithm initial values."""
        try:
            detections = []
            constants = CRYPTO_CONSTANTS[algorithm]["initial"]
            
            # Convert to little-endian byte pattern for search
            pattern_bytes = []
            for const in constants:
                pattern_bytes.extend([(const >> (i * 8)) & 0xFF for i in range(4)])
            
            pattern = "".join(f"{x:02x}" for x in pattern_bytes[:16])  # First 16 bytes
            
            results = r2_manager.execute_command(f"/xj {pattern}", session_id)
            if isinstance(results, str):
                results = json.loads(results)
            
            for result in results or []:
                offset = result.get("offset", 0)
                detections.append(
                    CryptoDetection(
                        algorithm=algorithm,
                        confidence=0.95,
                        offset=offset,
                        size=len(constants) * 4,
                        data=bytes(pattern_bytes),
                        matches=["initial_values"],
                        additional_info={
                            "type": "Initial Hash Values",
                            "description": f"{algorithm} initial hash constants"
                        }
                    )
                )
            
            return detections
            
        except Exception as e:
            logger.error(f"Failed to detect {algorithm} constants: {e}")
            return []

    @staticmethod
    async def _detect_rsa_exponents(session_id: Optional[str] = None) -> List[CryptoDetection]:
        """Detect common RSA exponents."""
        try:
            detections = []
            
            for exp in RSA_COMMON_EXPONENTS:
                # Search for exponent in little-endian format
                exp_bytes = [(exp >> (i * 8)) & 0xFF for i in range(4)]
                pattern = "".join(f"{x:02x}" for x in exp_bytes)
                
                results = r2_manager.execute_command(f"/xj {pattern}", session_id)
                if isinstance(results, str):
                    results = json.loads(results)
                
                for result in results or []:
                    offset = result.get("offset", 0)
                    detections.append(
                        CryptoDetection(
                            algorithm="RSA",
                            confidence=0.8,
                            offset=offset,
                            size=4,
                            data=bytes(exp_bytes),
                            matches=[f"exponent_{exp}"],
                            additional_info={
                                "type": "Public Exponent",
                                "description": f"RSA public exponent {exp}",
                                "value": exp
                            }
                        )
                    )
            
            return detections
            
        except Exception as e:
            logger.error(f"Failed to detect RSA exponents: {e}")
            return []

    @staticmethod
    async def _detect_base64_alphabet(session_id: Optional[str] = None) -> List[CryptoDetection]:
        """Detect Base64 alphabet string."""
        try:
            detections = []
            
            # Search for the standard Base64 alphabet
            alphabet_bytes = BASE64_ALPHABET.encode('ascii')
            pattern = alphabet_bytes[:16].hex()  # First 16 characters
            
            results = r2_manager.execute_command(f"/xj {pattern}", session_id)
            if isinstance(results, str):
                results = json.loads(results)
            
            for result in results or []:
                offset = result.get("offset", 0)
                
                # Verify this is the full alphabet
                full_data = r2_manager.execute_command(f"ps 64 @ {offset:#x}", session_id)
                if full_data and BASE64_ALPHABET in full_data:
                    detections.append(
                        CryptoDetection(
                            algorithm="BASE64",
                            confidence=0.95,
                            offset=offset,
                            size=len(alphabet_bytes),
                            data=alphabet_bytes,
                            matches=["standard_alphabet"],
                            additional_info={
                                "type": "Alphabet String",
                                "description": "Base64 encoding alphabet"
                            }
                        )
                    )
            
            return detections
            
        except Exception as e:
            logger.error(f"Failed to detect Base64 alphabet: {e}")
            return []

    @staticmethod
    async def detect_aes_key_schedule(session_id: Optional[str] = None) -> List[CryptoDetection]:
        """
        Detect AES key schedule patterns.
        Looks for expanded key patterns and key schedule operations.
        """
        try:
            detections = []
            
            # Detect round constant usage patterns
            for i, rcon in enumerate(AES_RCON[:10]):  # First 10 round constants
                # Search for round constant in context
                pattern = f"{rcon:02x}"
                
                # Look for patterns where round constants are used
                results = r2_manager.execute_command(f"/xj {pattern}", session_id)
                if isinstance(results, str):
                    results = json.loads(results)
                
                for result in results or []:
                    offset = result.get("offset", 0)
                    
                    # Check surrounding context for key schedule patterns
                    context = r2_manager.execute_command(f"px 32 @ {offset - 16:#x}", session_id)
                    if context and await CryptoDetectionTools._analyze_key_schedule_context(context):
                        detections.append(
                            CryptoDetection(
                                algorithm="AES",
                                confidence=0.8,
                                offset=offset,
                                size=32,
                                data=bytes([rcon]),
                                matches=[f"rcon_round_{i+1}"],
                                additional_info={
                                    "type": "Key Schedule",
                                    "description": f"AES key schedule round {i+1}",
                                    "round": i + 1,
                                    "round_constant": rcon
                                }
                            )
                        )
            
            # Detect expanded key patterns (128-bit keys = 176 bytes total)
            # Look for patterns that might be expanded AES keys
            detections.extend(await CryptoDetectionTools._detect_expanded_keys(session_id))
            
            return detections
            
        except Exception as e:
            logger.error(f"Failed to detect AES key schedule: {e}")
            return []

    @staticmethod
    async def _analyze_key_schedule_context(hex_context: str) -> bool:
        """Analyze hex context to determine if it's likely a key schedule operation."""
        try:
            # Look for patterns common in AES key expansion
            # - Multiple round constants nearby
            # - XOR operation patterns
            # - 4-byte aligned data
            
            lines = hex_context.strip().split('\n')
            hex_bytes = []
            
            for line in lines:
                if '  ' in line:
                    hex_part = line.split('  ', 1)[1].split('  ')[0]
                    bytes_in_line = hex_part.split()
                    hex_bytes.extend([int(b, 16) for b in bytes_in_line if len(b) == 2])
            
            # Check for multiple round constants in nearby data
            rcon_count = sum(1 for byte in hex_bytes if byte in AES_RCON[:10])
            
            # Check for patterns typical in key schedules
            # - Repeated 4-byte patterns
            # - Non-random distribution
            if rcon_count >= 2:
                return True
            
            # Check for 4-byte alignment patterns
            if len(hex_bytes) >= 16:
                four_byte_patterns = []
                for i in range(0, len(hex_bytes) - 3, 4):
                    pattern = tuple(hex_bytes[i:i+4])
                    four_byte_patterns.append(pattern)
                
                # Key schedules often have structured patterns
                unique_patterns = len(set(four_byte_patterns))
                if unique_patterns < len(four_byte_patterns) * 0.8:  # Some repetition
                    return True
            
            return False
            
        except Exception:
            return False

    @staticmethod
    async def _detect_expanded_keys(session_id: Optional[str] = None) -> List[CryptoDetection]:
        """Detect expanded AES key patterns."""
        try:
            detections = []
            
            # AES-128 expanded key is 176 bytes (11 rounds * 16 bytes)
            # AES-192 expanded key is 208 bytes (13 rounds * 16 bytes)  
            # AES-256 expanded key is 240 bytes (15 rounds * 16 bytes)
            
            key_sizes = [176, 208, 240]
            
            for key_size in key_sizes:
                # Look for memory regions that might contain expanded keys
                # Search for patterns with low entropy but structured data
                
                sections = r2_manager.execute_command("iSj", session_id)
                if isinstance(sections, str):
                    sections = json.loads(sections)
                
                for section in sections or []:
                    if section.get("perm", "").find("r") != -1:  # Readable section
                        start_addr = section.get("vaddr", 0)
                        size = section.get("size", 0)
                        
                        # Sample some offsets in this section
                        sample_points = min(10, size // key_size) if size > key_size else 1
                        
                        for i in range(sample_points):
                            offset = start_addr + (i * key_size)
                            
                            # Check if this looks like an expanded key
                            confidence = await CryptoDetectionTools._analyze_expanded_key_pattern(
                                offset, key_size, session_id
                            )
                            
                            if confidence > 0.7:
                                key_type = "AES-128" if key_size == 176 else \
                                          "AES-192" if key_size == 208 else "AES-256"
                                
                                detections.append(
                                    CryptoDetection(
                                        algorithm="AES",
                                        confidence=confidence,
                                        offset=offset,
                                        size=key_size,
                                        data=b"",  # Don't store actual key data
                                        matches=["expanded_key"],
                                        additional_info={
                                            "type": "Expanded Key",
                                            "description": f"{key_type} expanded key schedule",
                                            "key_type": key_type,
                                            "rounds": key_size // 16 - 1
                                        }
                                    )
                                )
            
            return detections
            
        except Exception as e:
            logger.error(f"Failed to detect expanded keys: {e}")
            return []

    @staticmethod
    async def _analyze_expanded_key_pattern(offset: int, size: int, session_id: Optional[str] = None) -> float:
        """Analyze if a memory region contains an expanded AES key."""
        try:
            # Read the data
            hex_data = r2_manager.execute_command(f"px {size} @ {offset:#x}", session_id)
            if not hex_data:
                return 0.0
            
            # Parse hex data
            lines = hex_data.strip().split('\n')
            hex_bytes = []
            
            for line in lines:
                if '  ' in line:
                    hex_part = line.split('  ', 1)[1].split('  ')[0]
                    bytes_in_line = hex_part.split()
                    hex_bytes.extend([int(b, 16) for b in bytes_in_line if len(b) == 2])
            
            if len(hex_bytes) < size:
                return 0.0
            
            # Analyze patterns typical of expanded keys
            confidence = 0.0
            
            # Check for round constants in expected positions
            rounds = size // 16
            rcon_found = 0
            
            for round_idx in range(1, min(rounds, 11)):  # First 10 rounds have known constants
                # Round constants appear in specific positions in the key schedule
                expected_pos = round_idx * 16
                if expected_pos < len(hex_bytes):
                    # Check nearby bytes for round constants
                    for check_pos in range(max(0, expected_pos - 4), min(len(hex_bytes), expected_pos + 4)):
                        if hex_bytes[check_pos] in AES_RCON:
                            rcon_found += 1
                            break
            
            if rcon_found > 0:
                confidence += 0.3 * min(1.0, rcon_found / 3)
            
            # Check for 16-byte alignment and structure
            rounds_data = []
            for i in range(0, len(hex_bytes), 16):
                if i + 16 <= len(hex_bytes):
                    round_key = hex_bytes[i:i+16]
                    rounds_data.append(round_key)
            
            if len(rounds_data) >= 2:
                # Check for XOR relationships between consecutive rounds
                # (simplified check)
                xor_patterns = 0
                for i in range(len(rounds_data) - 1):
                    xor_result = [a ^ b for a, b in zip(rounds_data[i], rounds_data[i+1])]
                    # Key schedule should show some structured XOR patterns
                    if any(x in AES_RCON for x in xor_result):
                        xor_patterns += 1
                
                if xor_patterns > 0:
                    confidence += 0.3 * min(1.0, xor_patterns / 3)
            
            # Check entropy - expanded keys should have medium entropy
            # (not too random, not too structured)
            if len(hex_bytes) > 32:
                byte_counts = [0] * 256
                for byte in hex_bytes:
                    byte_counts[byte] += 1
                
                # Calculate entropy
                entropy = 0.0
                total = len(hex_bytes)
                for count in byte_counts:
                    if count > 0:
                        p = count / total
                        entropy -= p * (p.bit_length() - 1) if p > 0 else 0
                
                # Good expanded keys have entropy between 6.5 and 7.5
                if 6.0 <= entropy <= 7.8:
                    confidence += 0.4
            
            return min(1.0, confidence)
            
        except Exception as e:
            logger.error(f"Failed to analyze expanded key pattern: {e}")
            return 0.0

    @staticmethod
    async def detect_des_permutation_tables(session_id: Optional[str] = None) -> List[CryptoDetection]:
        """
        Detect DES permutation tables (IP and FP).
        Searches for Initial Permutation and Final Permutation tables.
        """
        try:
            detections = []
            
            # Detect Initial Permutation (IP) table
            ip_detections = await CryptoDetectionTools._detect_des_ip_table(session_id)
            detections.extend(ip_detections)
            
            # Detect Final Permutation (FP) table  
            fp_detections = await CryptoDetectionTools._detect_des_fp_table(session_id)
            detections.extend(fp_detections)
            
            return detections
            
        except Exception as e:
            logger.error(f"Failed to detect DES permutation tables: {e}")
            return []

    @staticmethod
    async def _detect_des_ip_table(session_id: Optional[str] = None) -> List[CryptoDetection]:
        """Detect DES Initial Permutation table."""
        try:
            detections = []
            
            # Convert DES IP table to different possible formats
            # Format 1: As byte array (values 1-64)
            ip_bytes = bytes(DES_IP)
            pattern1 = ip_bytes[:16].hex()  # First 16 bytes
            
            # Format 2: As little-endian 32-bit integers
            ip_32bit = []
            for i in range(0, len(DES_IP), 4):
                if i + 4 <= len(DES_IP):
                    # Pack 4 bytes into a 32-bit integer (little-endian)
                    val = (DES_IP[i] | (DES_IP[i+1] << 8) | 
                           (DES_IP[i+2] << 16) | (DES_IP[i+3] << 24))
                    ip_32bit.append(val)
            
            # Convert to bytes for pattern matching
            pattern2_bytes = []
            for val in ip_32bit[:4]:  # First 4 32-bit values
                pattern2_bytes.extend([(val >> (i * 8)) & 0xFF for i in range(4)])
            pattern2 = bytes(pattern2_bytes).hex()
            
            # Search for both patterns
            for pattern, format_name in [(pattern1, "byte_array"), (pattern2, "32bit_array")]:
                results = r2_manager.execute_command(f"/xj {pattern}", session_id)
                if isinstance(results, str):
                    results = json.loads(results)
                
                for result in results or []:
                    offset = result.get("offset", 0)
                    
                    # Verify this is actually the DES IP table
                    confidence = await CryptoDetectionTools._verify_des_ip_table(
                        offset, format_name, session_id
                    )
                    
                    if confidence > 0.8:
                        detections.append(
                            CryptoDetection(
                                algorithm="DES",
                                confidence=confidence,
                                offset=offset,
                                size=len(DES_IP) * (1 if format_name == "byte_array" else 4),
                                data=ip_bytes if format_name == "byte_array" else bytes(pattern2_bytes),
                                matches=["initial_permutation"],
                                additional_info={
                                    "type": "Initial Permutation Table",
                                    "description": "DES Initial Permutation (IP) table",
                                    "format": format_name
                                }
                            )
                        )
            
            return detections
            
        except Exception as e:
            logger.error(f"Failed to detect DES IP table: {e}")
            return []

    @staticmethod
    async def _detect_des_fp_table(session_id: Optional[str] = None) -> List[CryptoDetection]:
        """Detect DES Final Permutation table."""
        try:
            detections = []
            
            # Convert DES FP table to different possible formats
            fp_bytes = bytes(DES_FP)
            pattern1 = fp_bytes[:16].hex()  # First 16 bytes
            
            # Format as 32-bit integers
            fp_32bit = []
            for i in range(0, len(DES_FP), 4):
                if i + 4 <= len(DES_FP):
                    val = (DES_FP[i] | (DES_FP[i+1] << 8) | 
                           (DES_FP[i+2] << 16) | (DES_FP[i+3] << 24))
                    fp_32bit.append(val)
            
            pattern2_bytes = []
            for val in fp_32bit[:4]:
                pattern2_bytes.extend([(val >> (i * 8)) & 0xFF for i in range(4)])
            pattern2 = bytes(pattern2_bytes).hex()
            
            # Search for both patterns
            for pattern, format_name in [(pattern1, "byte_array"), (pattern2, "32bit_array")]:
                results = r2_manager.execute_command(f"/xj {pattern}", session_id)
                if isinstance(results, str):
                    results = json.loads(results)
                
                for result in results or []:
                    offset = result.get("offset", 0)
                    
                    # Verify this is actually the DES FP table
                    confidence = await CryptoDetectionTools._verify_des_fp_table(
                        offset, format_name, session_id
                    )
                    
                    if confidence > 0.8:
                        detections.append(
                            CryptoDetection(
                                algorithm="DES",
                                confidence=confidence,
                                offset=offset,
                                size=len(DES_FP) * (1 if format_name == "byte_array" else 4),
                                data=fp_bytes if format_name == "byte_array" else bytes(pattern2_bytes),
                                matches=["final_permutation"],
                                additional_info={
                                    "type": "Final Permutation Table",
                                    "description": "DES Final Permutation (FP) table",
                                    "format": format_name
                                }
                            )
                        )
            
            return detections
            
        except Exception as e:
            logger.error(f"Failed to detect DES FP table: {e}")
            return []

    @staticmethod
    async def _verify_des_ip_table(offset: int, format_name: str, session_id: Optional[str] = None) -> float:
        """Verify if data at offset is DES Initial Permutation table."""
        try:
            # Calculate expected size
            expected_size = len(DES_IP) * (1 if format_name == "byte_array" else 4)
            
            # Read the data
            hex_data = r2_manager.execute_command(f"px {expected_size} @ {offset:#x}", session_id)
            if not hex_data:
                return 0.0
            
            # Parse hex data
            lines = hex_data.strip().split('\n')
            hex_bytes = []
            
            for line in lines:
                if '  ' in line:
                    hex_part = line.split('  ', 1)[1].split('  ')[0]
                    bytes_in_line = hex_part.split()
                    hex_bytes.extend([int(b, 16) for b in bytes_in_line if len(b) == 2])
            
            if len(hex_bytes) < expected_size:
                return 0.0
            
            # Convert back to values for comparison
            if format_name == "byte_array":
                values = hex_bytes[:len(DES_IP)]
            else:  # 32bit_array
                values = []
                for i in range(0, len(hex_bytes), 4):
                    if i + 4 <= len(hex_bytes):
                        val = (hex_bytes[i] | (hex_bytes[i+1] << 8) | 
                               (hex_bytes[i+2] << 16) | (hex_bytes[i+3] << 24))
                        values.append(val)
            
            # Compare with expected DES IP table
            matches = 0
            for i, expected in enumerate(DES_IP):
                if i < len(values) and values[i] == expected:
                    matches += 1
            
            return matches / len(DES_IP)
            
        except Exception as e:
            logger.error(f"Failed to verify DES IP table: {e}")
            return 0.0

    @staticmethod
    async def _verify_des_fp_table(offset: int, format_name: str, session_id: Optional[str] = None) -> float:
        """Verify if data at offset is DES Final Permutation table."""
        try:
            # Calculate expected size
            expected_size = len(DES_FP) * (1 if format_name == "byte_array" else 4)
            
            # Read the data
            hex_data = r2_manager.execute_command(f"px {expected_size} @ {offset:#x}", session_id)
            if not hex_data:
                return 0.0
            
            # Parse hex data
            lines = hex_data.strip().split('\n')
            hex_bytes = []
            
            for line in lines:
                if '  ' in line:
                    hex_part = line.split('  ', 1)[1].split('  ')[0]
                    bytes_in_line = hex_part.split()
                    hex_bytes.extend([int(b, 16) for b in bytes_in_line if len(b) == 2])
            
            if len(hex_bytes) < expected_size:
                return 0.0
            
            # Convert back to values for comparison
            if format_name == "byte_array":
                values = hex_bytes[:len(DES_FP)]
            else:  # 32bit_array
                values = []
                for i in range(0, len(hex_bytes), 4):
                    if i + 4 <= len(hex_bytes):
                        val = (hex_bytes[i] | (hex_bytes[i+1] << 8) | 
                               (hex_bytes[i+2] << 16) | (hex_bytes[i+3] << 24))
                        values.append(val)
            
            # Compare with expected DES FP table
            matches = 0
            for i, expected in enumerate(DES_FP):
                if i < len(values) and values[i] == expected:
                    matches += 1
            
            return matches / len(DES_FP)
            
        except Exception as e:
            logger.error(f"Failed to verify DES FP table: {e}")
            return 0.0


# MCP Tool Wrappers

@mcp.tool()
async def detect_aes_sbox(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Detect AES S-Box patterns in the binary.
    Searches for both forward and inverse substitution boxes.
    """
    detections = await CryptoDetectionTools.detect_aes_sbox(session_id)
    return [d.dict() for d in detections]


@mcp.tool()
async def detect_crypto_constants(
    algorithm: str, session_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Detect cryptographic constants for a specific algorithm.
    
    Args:
        algorithm: Algorithm name (AES, DES, SHA1, SHA256, MD5, RSA, BASE64, etc.)
        session_id: Session to use
    """
    detections = await CryptoDetectionTools.detect_crypto_constants(algorithm, session_id)
    return [d.dict() for d in detections]


@mcp.tool()
async def detect_aes_key_schedule(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Detect AES key schedule patterns.
    Looks for expanded key patterns and key schedule operations.
    """
    detections = await CryptoDetectionTools.detect_aes_key_schedule(session_id)
    return [d.dict() for d in detections]


@mcp.tool()
async def detect_des_permutation_tables(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Detect DES permutation tables (Initial and Final Permutation).
    Searches for DES IP and FP tables in both byte array and 32-bit integer formats.
    """
    detections = await CryptoDetectionTools.detect_des_permutation_tables(session_id)
    return [d.dict() for d in detections]


@mcp.tool()
async def scan_all_crypto_patterns(session_id: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Comprehensive scan for all supported cryptographic patterns.
    Returns a dictionary with algorithm names as keys and detection results as values.
    """
    try:
        all_detections = {}
        
        # Scan for each supported algorithm
        algorithms = ["AES", "DES", "SHA1", "SHA256", "MD5", "RSA", "BASE64"]
        
        for algo in algorithms:
            detections = await CryptoDetectionTools.detect_crypto_constants(algo, session_id)
            if detections:
                all_detections[algo] = [d.dict() for d in detections]
        
        return all_detections
        
    except Exception as e:
        logger.error(f"Failed to scan crypto patterns: {e}")
        return {}


@mcp.tool()
async def get_crypto_constant_info(algorithm: str) -> Dict[str, Any]:
    """
    Get information about cryptographic constants for a specific algorithm.
    
    Args:
        algorithm: Algorithm name (AES, DES, SHA1, SHA256, MD5, RSA, etc.)
    """
    try:
        if algorithm.upper() not in CRYPTO_CONSTANTS:
            return {"error": f"Algorithm {algorithm} not supported"}
        
        constants = CRYPTO_CONSTANTS[algorithm.upper()]
        result = {
            "algorithm": algorithm.upper(),
            "name": constants.get("name", ""),
            "constants": {}
        }
        
        # Add specific constant information
        for key, value in constants.items():
            if key != "name":
                if isinstance(value, list):
                    if all(isinstance(x, int) and 0 <= x <= 255 for x in value):
                        # Byte array
                        result["constants"][key] = {
                            "type": "byte_array",
                            "size": len(value),
                            "hex": "".join(f"{x:02x}" for x in value[:16]) + ("..." if len(value) > 16 else "")
                        }
                    else:
                        # Integer array
                        result["constants"][key] = {
                            "type": "integer_array",
                            "size": len(value),
                            "values": value[:8] + ["..."] if len(value) > 8 else value
                        }
                elif isinstance(value, int):
                    result["constants"][key] = {
                        "type": "integer",
                        "value": value,
                        "hex": f"0x{value:x}"
                    }
                elif isinstance(value, str):
                    result["constants"][key] = {
                        "type": "string",
                        "value": value,
                        "length": len(value)
                    }
                elif isinstance(value, dict):
                    result["constants"][key] = {
                        "type": "dictionary",
                        "keys": list(value.keys())
                    }
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to get crypto constant info: {e}")
        return {"error": str(e)}