import pathlib
from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent

VERSION = '1.0.0'
PACKAGE_NAME = 'weaveapi'
AUTHOR = 'You'
AUTHOR_EMAIL = 'support@weavechain.com'
URL = 'https://github.com/weavechain/weavechain'

LICENSE = 'MIT License'
DESCRIPTION = 'weavechain API'
LONG_DESCRIPTION = (HERE / "README.md").read_text()
LONG_DESC_TYPE = "text/markdown"

INSTALL_REQUIRES = [
      'demjson',
      'requests',
      'websocket-client',
      'cryptography',
      'PyCryptodome'
]

setup(name=PACKAGE_NAME,
      version=VERSION,
      description=DESCRIPTION,
      long_description=LONG_DESCRIPTION,
      long_description_content_type=LONG_DESC_TYPE,
      author=AUTHOR,
      license=LICENSE,
      author_email=AUTHOR_EMAIL,
      url=URL,
      install_requires=INSTALL_REQUIRES,
      packages=find_packages()
      )