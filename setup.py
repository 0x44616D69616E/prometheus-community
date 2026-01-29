"""
Prometheus Community Edition - Setup Configuration

Revolutionary 6-layer malware analysis with explainable detection and location tracking.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="prometheus-community",
    version="2.0.0",
    
    # Author information
    author="Damian Donahue",
    author_email="contact@asnspy.com",
    
    # Description
    description="The most transparent malware analyzer - Explainable detection with forensic-grade location tracking",
    long_description=long_description,
    long_description_content_type="text/markdown",
    
    # URLs
    url="https://github.com/0x44616D69616E/prometheus-community",
    project_urls={
        "Bug Tracker": "https://github.com/0x44616D69616E/prometheus-community/issues",
        "Documentation": "https://github.com/0x44616D69616E/prometheus-community/blob/main/docs",
        "Source Code": "https://github.com/0x44616D69616E/prometheus-community",
        "Enterprise Edition": "https://github.com/0x44616D69616E/prometheus-enterprise",
        "Discussions": "https://github.com/0x44616D69616E/prometheus-community/discussions",
        "Research Paper": "https://doi.org/10.5281/zenodo.18123287",
    },
    
    # License
    license="Prometheus Community License v1.0",
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    
    # Package configuration
    packages=find_packages(),
    python_requires=">=3.8",
    
    # No external dependencies for community edition
    # (Enterprise edition has FastAPI, etc.)
    install_requires=[],
    
    # CLI entry point
    entry_points={
        "console_scripts": [
            "prometheus=prometheus.cli:main",
        ],
    },
    
    # Include package data (enhanced intelligence database)
    package_data={
        "prometheus": [
            "data/*.json",
        ],
    },
    include_package_data=True,
    
    # Keywords for PyPI search
    keywords=[
        "malware analysis",
        "explainable AI",
        "security",
        "threat intelligence",
        "cybersecurity",
        "reverse engineering",
        "malware detection",
        "behavioral analysis",
        "exploit detection",
        "knowledge graph",
        "security research",
        "forensics",
        "MITRE ATT&CK",
        "transparent detection",
        "location tracking",
    ],
    
    # Zip safe
    zip_safe=False,
)
