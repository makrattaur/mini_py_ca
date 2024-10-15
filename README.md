# mini_py_ca

A minimal and simple root certification authority.

Useful in a 2-tier PKI hierarchy where this project acts as a offline root.


## Setup

The project can be either installed from a built wheel from the `setup.py` or using `pip`'s various install sources.


## Quick start

1. Generate the CA key with `mca-gen-key`.
2. Generate the CA certificate with `mca-gen-ca-cert`.
3. Generate the initial CRL with `mca-gen-crl`.
4. Sign a subordinate CA with `mca-sign-csr`.
5. At the interval indicated by the CRL, regenerate the CRL with `mca-gen-crl`.

