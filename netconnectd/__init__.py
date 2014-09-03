from __future__ import (print_function, absolute_import)

from .client import client
from .server import server



from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
