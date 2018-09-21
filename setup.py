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
    entry_points = {
        "console_scripts": [
            "mca-gen-key=mini_py_ca.commands.gen_key:main",
            "mca-key-mgr=mini_py_ca.commands.key_mgr:main",
            "mca-gen-ca-cert=mini_py_ca.commands.gen_ca_cert:main",
            "mca-sign-csr=mini_py_ca.commands.sign_csr:main",
            "mca-revoke-cert=mini_py_ca.commands.revoke_cert:main",
            "mca-gen-crl=mini_py_ca.commands.gen_crl:main",
            "mca-active-certs=mini_py_ca.commands.active_certificates:main",
        ]
    },
)


