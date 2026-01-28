"""
PROMETHEUS COMMUNITY EDITION

Revolutionary 6-layer malware analysis with knowledge graph intelligence.

Free for research, education, and non-profit use.
For commercial licensing, contact: contact@asnspy.com

Copyright (c) 2026 Damian Donahue
License: Prometheus Community License v1.0 (see LICENSE file)
"""

__version__ = "1.0.0"
__author__ = "Damian Donahue"
__email__ = "contact@asnspy.com"
__license__ = "Prometheus Community License v1.0"

from .engine import PrometheusEngine
from .models import (
    Sample,
    AnalysisResult,
    FileType,
    Platform,
)

__all__ = [
    'PrometheusEngine',
    'Sample',
    'AnalysisResult',
    'FileType',
    'Platform',
]
