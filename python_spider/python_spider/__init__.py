from . import trans
from . import settings

if settings.LOCAL_TRANS:
    trans.init()
