
from setuptools import setup, Extension
from Cython.Build import cythonize
import os

extra_compile_args = [
    "-O3","-march=native","-mtune=native","-fno-plt","-pipe",
    "-flto","-fomit-frame-pointer","-funroll-loops",
]
extra_link_args = ["-flto"]

extensions = [
    Extension(
        "proxy",
        sources=["proxy.pyx"],
        libraries=[],
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
    )
]

setup(
    name="proxy_fast",
    version="0.1.0",
    ext_modules=cythonize(extensions, language_level=3, annotate=False, nthreads=os.cpu_count() or 4),
)
