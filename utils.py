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

def get_func_extents(func):
    addr_set = func.getBody()
    min_addr, max_addr = addr_set.getMinAddress(), addr_set.getMaxAddress()
    return min_addr, max_addr

def format_loc(api_base, addr_int):
    func = api_base.getFunctionContaining(api_base.toAddr(addr_int))
    func_st_addr, _ = get_func_extents(func)
    func_st = func_st_addr.offset
    loc_diff = addr_int - func_st
    return "{}+0x{:x}(0x{:x})".format(func.name, loc_diff, addr_int)
