"""
PROMETHEUS COMMUNITY EDITION v2.0.0

The most transparent malware analyzer available.

Revolutionary 6-layer analysis with explainable detection and forensic-grade 
location tracking. Every finding explained with WHY it matters and WHERE it's located.

Free for research, education, and non-profit use.
For commercial licensing, contact: contact@asnspy.com

Copyright (c) 2026 Damian Donahue
License: Prometheus Community License v1.0 (see LICENSE file)
"""

__version__ = "2.0.0"
__author__ = "Damian Donahue"
__email__ = "contact@asnspy.com"
__license__ = "Prometheus Community License v1.0"

from .engine import PrometheusEngine
from .models import (
    Sample,
    AnalysisResult,
    FileType,
    Platform,
    Severity,
    Uniqueness,
    Location,
    BehavioralMatch,
    ExploitMatch,
    SignatureMatch,
    DetectionReasoning,
)

__all__ = [
    'PrometheusEngine',
    'Sample',
    'AnalysisResult',
    'FileType',
    'Platform',
    'Severity',
    'Uniqueness',
    'Location',
    'BehavioralMatch',
    'ExploitMatch',
    'SignatureMatch',
    'DetectionReasoning',
]
