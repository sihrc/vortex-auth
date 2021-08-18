#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name="vortex-http-auth",
    version="0.1.0",
    description="JWT Authentication plugin for vortex-http",
    author="Chris Lee",
    author_email="sihrc.c.lee@gmail.com",
    packages=find_packages(),
    install_requires=[
        "PyJWT==1.7.1",
        "setuptools>=57.4.0",
        "wheel>=0.35.1",
    ],
    extras_require={"testing": ["pytest", "pytest-aiohttp"]},
)
