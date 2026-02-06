"""
PROMETHEUS - CONFIGURATION SYSTEM

User-configurable settings for analysis behavior.

Copyright (c) 2026 Damian Donahue
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional


class ValidationStrictness(Enum):
    """Validation strictness levels for context-aware detection."""
    STRICT = "strict"      # Requires path separators AND common paths
    MODERATE = "moderate"  # Requires path separator OR file-like structure  
    LENIENT = "lenient"    # Minimal validation, catches more but may have false positives


@dataclass
class PrometheusConfig:
    """
    Configuration for Prometheus analysis engine.
    
    Controls behavior of detection layers and output formatting.
    """
    
    # Validation settings
    validation_strictness: ValidationStrictness = ValidationStrictness.MODERATE
    enable_context_validation: bool = True
    
    # Output settings
    quiet_mode: bool = False
    verbose_output: bool = True
    show_hex_context: bool = True
    max_artifacts_displayed: int = 10
    
    # Detection layer toggles
    enable_signature_scanning: bool = True
    enable_behavioral_detection: bool = True
    enable_exploit_detection: bool = True
    enable_file_type_validation: bool = True
    
    # Advanced detection modules (Block 2)
    enable_steganography_detection: bool = True
    enable_shellcode_detection: bool = True
    enable_xor_encoding_detection: bool = True
    enable_nested_file_detection: bool = True
    
    # Block 2 - Advanced detection toggles
    enable_steganography_detection: bool = True
    enable_shellcode_detection: bool = True
    enable_xor_encoding_detection: bool = True
    enable_nested_file_detection: bool = True
    
    # Block 3 - Executable analysis toggles
    enable_pe_analysis: bool = True
    enable_anti_analysis_detection: bool = True
    enable_crypto_detection: bool = True
    
    # Block 4 - Cross-platform & network toggles
    enable_elf_analysis: bool = True
    enable_string_analysis: bool = True
    enable_network_detection: bool = True
    
    # Block 5 - Intelligence automation toggles
    enable_android_analysis: bool = True
    enable_yara_generation: bool = True
    enable_ioc_export: bool = True
    enable_report_generation: bool = True
    
    # Intelligence database
    intelligence_database_path: Optional[str] = None
    
    # Performance settings
    max_string_length: int = 10000  # Max string length to analyze
    entropy_sample_size: int = 4096  # Bytes to sample for entropy calculation
    
    @classmethod
    def default(cls) -> 'PrometheusConfig':
        """Return default configuration."""
        return cls()
    
    @classmethod
    def strict(cls) -> 'PrometheusConfig':
        """Return strict validation configuration."""
        config = cls()
        config.validation_strictness = ValidationStrictness.STRICT
        return config
    
    @classmethod
    def lenient(cls) -> 'PrometheusConfig':
        """Return lenient validation configuration."""
        config = cls()
        config.validation_strictness = ValidationStrictness.LENIENT
        return config
    
    def get_validation_rules(self) -> dict:
        """
        Get validation rules based on strictness level.
        
        Returns:
            Dictionary of validation parameters
        """
        if self.validation_strictness == ValidationStrictness.STRICT:
            return {
                'require_path_separator': True,
                'require_common_paths': True,
                'min_path_length': 5,
                'allow_bare_extensions': False,
                'require_url_scheme': True,
                'require_valid_ip_format': True,
                'require_registry_root': True
            }
        elif self.validation_strictness == ValidationStrictness.MODERATE:
            return {
                'require_path_separator': False,  # OR file-like structure
                'require_common_paths': False,
                'min_path_length': 3,
                'allow_bare_extensions': True,
                'require_url_scheme': False,
                'require_valid_ip_format': True,
                'require_registry_root': False
            }
        else:  # LENIENT
            return {
                'require_path_separator': False,
                'require_common_paths': False,
                'min_path_length': 1,
                'allow_bare_extensions': True,
                'require_url_scheme': False,
                'require_valid_ip_format': False,
                'require_registry_root': False
            }


# Global default configuration
DEFAULT_CONFIG = PrometheusConfig.default()
