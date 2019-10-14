import logging

from .x86 import x86

logger = logging.getLogger(__name__)

class x64(x86):
    LANG_DESC = "x86/.*/64/.*"
    INIT_STACK_SIZE = 0x100000
    base_ptr = "RBP"

    # Must come after the functions are defined...
    callother_dict = {
            }
