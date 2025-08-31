from setuptools import setup
from Cython.Build import cythonize

setup(ext_modules=cythonize("proxy.pyx", language_level="3"))
