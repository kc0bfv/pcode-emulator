class UniqueMarker(object):
    """Subclasses may be stored in "memory" of the Uniques.  These
    can then be used as markers for other parts of the emulator code.  Ghidra
    won't understand them, they're just for marking points in Unique memory
    between pcode operations in the same assembly instruction.
    """
    pass

class CallOtherMarker(UniqueMarker):
    """This UniqueMarker indicates that a CallOther has occurred, and the
    program should interpret the return value as a "just keep going" instead
    of as a memory location of a function pointer.
    """
    pass
