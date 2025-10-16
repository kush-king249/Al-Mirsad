#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="al-mirsad",
    version="1.0.0",
    author="Hassan Mohamed Hassan Ahmed",
    author_email="",
    description="أداة أتمتة للاستجابة للحوادث الأمنية - Incident Response Automation Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kush-king249/Al-Mirsad",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "al-mirsad=cli.main_cli:main",
            "al-mirsad-gui=gui.main_gui:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
