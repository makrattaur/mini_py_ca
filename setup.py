#!/usr/bin/env python3


from setuptools import setup


setup(
    name = "mini_py_ca",
    version = "0.0.1",
    description = "Minimal and simple root certification authority",
    packages = [ "mini_py_ca", "mini_py_ca.commands" ],
    install_requires = [
        "cryptography>=2.2.2",
        "ruamel.yaml>=0.15.42",
    ],
)


