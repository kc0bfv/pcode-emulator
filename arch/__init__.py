import logging
import re
import types

from ..utils import find_all_subclasses
from .arch_class import LE, BE, Architecture

from .x86 import x86
from .x64 import x64
from .ARM import ARM

def instantiate_architecture(api_base):
    """Instantiate the proper architecture for the current program

    :param api_base: The object from which Ghidra has derived the flat api
    :type api_base: ghidra.python.PythonScript

    :return: An appropriate architecture for the current program, or None
    :rtype: Architecture or None
    """
    lang_desc = str(api_base.getCurrentProgram().getLanguage().
            getLanguageDescription())
    def yield_arch_match():
        for arch in find_all_subclasses(Architecture):
            logging.debug("Arch lang desc {} prgm {}".format(
                    arch.LANG_DESC, lang_desc)
                )
            try:
                if re.match(arch.LANG_DESC, lang_desc):
                    yield arch(api_base)
            except TypeError as e:
                # Occurs when an architecture has None as it's LANG_DESC
                pass

    matching_arches = [mtch for mtch in yield_arch_match()]
    if len(matching_arches) != 1:
        logging.error("Found wrong number of architecture matches: {}"
                "".format(matching_arches))
        return None
    return matching_arches[0]
