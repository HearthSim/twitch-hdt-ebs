#!/usr/bin/env python

from setuptools import setup


setup(
	# The following lets us find the hearthsim_identity egg.
	# https://github.com/pypa/pip/issues/4187
	dependency_links=[
		"https://github.com/HearthSim/hearthsim-identity/archive/master.zip"
		"#egg=hearthsim_identity-1.0.1"
	]
)
