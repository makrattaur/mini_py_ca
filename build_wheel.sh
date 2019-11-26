#!/bin/sh


if command -v python3 ; then
	# python3 is python3.
	pythonCmd=python3
else
	# maybe python is python3.
	pythonCmd=python
fi

${pythonCmd} setup.py sdist bdist_wheel


