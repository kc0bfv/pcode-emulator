#Emulates pcode execution.  Click on a function in the decompiler window, provide the initial parameters, and go!
#@author Karl Sickendick kc0bfv@gmail.com
#@category PCode
#@keybinding 
#@menupath 
#@toolbar 


from __future__ import print_function

import code
import logging

from ghidra_pcode_interpreter.state import State
from ghidra_pcode_interpreter.utils import get_api_base, get_func_extents, \
        format_loc

logger = logging.getLogger(__name__)

PRINT_LOCATION_EVERY = 100

def get_parameters(func):
    def get_param_val(param):
        ret = None
        while ret is None:
            ret = askInt("Parameter Entry",
                    "Specify integer value for parameter "
                    "{} {} type {} ".format(
                        param.getOrdinal(), param.getName(),
                        param.getDataType()
                        )
                    )
        return ret

    params = func.getParameters()
    if len(params) == 0:
        logger.warn("No parameters - did you commit the locals/params for "
                "the func?")

    return [(param, get_param_val(param)) for param in params]

def run_pcode(func, state, stop_addr):
    cur_loc = state.get_pc()
    api_base = get_api_base(getFunctionAt)
    index = 0
    while cur_loc != stop_addr:
        if index % PRINT_LOCATION_EVERY == 0:
            logging.info("Current location: {}".format(
                    format_loc(api_base, cur_loc))
                    )
        index += 1
        #setCurrentLocation(toAddr(cur_loc)) // Really slows things down
        cur_loc = state.execute_cur_location()
        logging.debug("State: {}".format(state))

def analyze_func_at(addr):
    """Emulate the function containing an address

    :param addr: An address in the function of interest
    :type addr: int
    """
    # Setup necessary emulator state 
    # TODO Move this somewhere better
    state = State(get_api_base(getInstructionAt))
    state.ram.store(0x08, 8, 0x0000000000414141)
    state.ram.store(0x10, 8, 0x0000000000333231)
    state.ram.store(0x18, 8, 0x0000000000000000)
    state.ram.store(0x20, 8, 0x0041414141414141)

    # Find the function surrounding addr
    containing_func = None
    try:
        containing_func = getFunctionContaining(addr)
    except:
        pass
    if containing_func is None:
        logger.error("Could not get containing function for selection")
        return

    # Input and store the function parameters
    param_inputs = get_parameters(containing_func)
    for param, param_val in param_inputs:
        param_vn = param.getFirstStorageVarnode()
        state.set_varnode(param_vn, param_val)

    start_point, func_end = get_func_extents(containing_func)
    logger.debug("Func body {} - {}".format(start_point, func_end))

    # Emulate the conditions of a function call
    state.setup_stack()
    state.fake_function_call(start_point.offset)

    # Run the code in the function
    run_pcode(containing_func, state, state.arch.sentinel_return_addr)

    # Read the return value
    return_obj = containing_func.getReturn()
    return_varnode = return_obj.getFirstStorageVarnode()
    orig_outval = state.read_varnode(return_varnode)

    # Determine if output should be interpreted as signed
    interpret_as_signed = False
    try:
        interpret_as_signed = return_obj.getDataType().isSigned()
    except:
        pass

    # Interpret outval as signed if necessary
    outval = orig_outval
    if interpret_as_signed:
        bit_count = return_varnode.size * state.arch.bits_per_byte
        sign = (outval >> (bit_count - 1)) & 1
        if sign == 1:
            outval = -((~outval & (2**64 - 1)) + 1)

    logger.info("Final state: {}".format(state))
    logger.info("Output value: {} or 0x{:x}".format(outval, orig_outval))

def main():
    logging.basicConfig(level=logging.DEBUG, 
            filename="/tmp/pcode_interpret.log", filemode="w")
    l_sh = logging.StreamHandler()
    l_sh.setLevel(logging.INFO)
    logging.getLogger('').addHandler(l_sh)

    curr_addr = 0
    if currentLocation is None:
        curr_addr = askAddress("Starting Address", "Provide starting address:")
    else:
        curr_addr = currentLocation.address

    analyze_func_at(curr_addr)

if __name__ == "__main__":
    main()
