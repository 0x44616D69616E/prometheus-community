"""
Prometheus Community Edition - Setup Configuration

Enterprise-grade malware analysis engine with 95% academic coverage.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="prometheus-community",
    version="3.0.3",
    
    # Author information
    author="Damian Donahue",
    author_email="contact@asnspy.com",
    
    # Description
    description="Enterprise-grade malware analysis engine - Windows/Linux/Android support with YARA generation and IOC export",
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
        "Changelog": "https://github.com/0x44616D69616E/prometheus-community/blob/main/CHANGELOG.md",
    },
    
    # License
    license="Prometheus Community License v1.0",
    
    # Classifiers
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    
    # Package configuration
    packages=find_packages(exclude=["tests", "tests.*", "docs", "docs.*"]),
    python_requires=">=3.8",
    
    # No external dependencies - Python stdlib only!
    # This is a key feature for enterprise deployment
    install_requires=[],
    
    # Optional dependencies for development
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    
    # CLI entry point
    entry_points={
        "console_scripts": [
            "prometheus=prometheus.cli:main",
        ],
    },
    
    # Include package data (intelligence database)
    package_data={
        "prometheus": [
            "data/*.json",
        ],
    },
    include_package_data=True,
    
    # Keywords for PyPI search
    keywords=[
        "malware analysis",
        "malware detection",
        "security",
        "threat intelligence",
        "cybersecurity",
        "reverse engineering",
        "behavioral analysis",
        "exploit detection",
        "forensics",
        "MITRE ATT&CK",
        "YARA",
        "IOC",
        "STIX",
        "Windows PE",
        "Linux ELF",
        "Android APK",
        "steganography",
        "shellcode",
        "packer detection",
        "anti-analysis",
        "cryptography",
        "network analysis",
        "threat hunting",
        "incident response",
        "SOC",
        "binary analysis",
    ],
    
    # Zip safe
    zip_safe=False,
)
