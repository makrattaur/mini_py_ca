#!/bin/sh

pip install --no-index --find-links offline_deps offline_deps/wheel-*.whl
pip install --no-index --find-links offline_deps dist/*.whl


