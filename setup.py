# setup.py
import os

from setuptools import setup
from Cython.Build import cythonize

# 获取当前文件的绝对路径
ROOT = os.path.dirname(os.path.abspath(__file__))
def absPaths(paths=''):
    return os.path.join(ROOT, paths)

setup(
    name='KsaSocket',
    version='1.0',
    ext_modules=cythonize([
        absPaths("KsaClient.pyx"),
        absPaths("KsaCoder.pyx"),
        absPaths("KsaLogger.pyx"),
        absPaths("KsaRequestParse.pyx"),
        absPaths("KsaServer.pyx"),
        absPaths("Csocket.pyx"),
    ]),
)
# python setup.py build_ext --inplace