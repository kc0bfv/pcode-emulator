import itertools as it

def get_api_base(api_func):
    """Return the API base for Ghidra's flat API

    :param api_func: Any function in Ghidra's flat API - eg. getInstructionAt
    :type: function

    :return: The api base
    :rtype: ghidra.python.PythonScript
    """
    return api_func.__self__

def find_all_subclasses(parent):
    """Return all descendents of the parent class.  This requires all
    subclasses to be part of the calling scope.

    :param parent: The parent class
    :type parent: class

    :return: A set of all subclasses
    :rtype: set
    """
    # Iteratively expand parent's subclasses, then drop parent
    all_insts = {parent}
    prev_size = 0
    while prev_size != len(all_insts):
        prev_size = len(all_insts)
        all_insts |= set(it.chain.from_iterable(inst.__subclasses__() 
                for inst in all_insts))

    all_insts.discard(parent)
    return all_insts
