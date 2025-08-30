from setuptools import setup, Extension
from Cython.Build import cythonize
import sys

extra_compile_args = ["-O3", "-march=native", "-fno-strict-aliasing"]
if sys.platform != "win32":
    extra_compile_args += ["-fvisibility=hidden"]

extensions = [
    Extension(
        name="proxy",
        sources=["proxy.pyx"],
        extra_compile_args=extra_compile_args,
        libraries=[],
    )
]

setup(
    name="ultra_proxy",
    version="1.0.0",
    ext_modules=cythonize(
        extensions,
        language_level=3,
        annotate=False,
        compiler_directives={
            "boundscheck": False,
            "wraparound": False,
            "cdivision": True,
            "initializedcheck": False,
            "nonecheck": False,
            "embedsignature": False,
        },
    ),
)
