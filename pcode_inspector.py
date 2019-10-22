#Prints information about pcode.  Click on a function in the decompiler window, run this.
#@author Karl Sickendick kc0bfv@gmail.com
#@category PCode
#@keybinding 
#@menupath 
#@toolbar 


from __future__ import print_function

import logging

from ghidra_pcode_interpreter.mem import InvalidAddrException
from ghidra_pcode_interpreter.state import State
from ghidra_pcode_interpreter.utils import get_api_base, get_func_extents

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

def print_pcode_info(func, state, stop_addr):
    cur_loc = state.get_pc()
    while cur_loc <= stop_addr:
        logging.info("Current location: 0x{:x}".format(cur_loc))
        try:
            cur_loc = state.inspect_cur_location()
        except InvalidAddrException as e:
            logging.info("No code at location")
            state.set_pc(state.get_pc() + 1)
            cur_loc = state.get_pc()

def main():
    logging.basicConfig(level=logging.DEBUG)
    curr_addr = 0
    if currentLocation is None:
        curr_addr = askAddress("Starting Address", "Provide starting address:")
    else:
        curr_addr = currentLocation.address

    # Build the emulator state
    state = State(get_api_base(getInstructionAt))

    # Determine the function of concern
    containing_func = None
    try:
        containing_func = getFunctionContaining(curr_addr)
    except:
        pass
    if containing_func is None:
        logger.error("Could not get containing function for selection")
        exit(1)

    # Print some function info
    start_point, func_end = get_func_extents(containing_func)
    logger.debug("Func body {} - {}".format(start_point, func_end))

    state.setup_stack()
    state.fake_function_call(start_point.offset)

    # Print state and architecture information
    logging.info("State info: {}".format(state))
    logging.info("Architecture info: {}".format(state.arch))

    # Print some parameter info
    params = containing_func.getParameters()
    logger.info("Parameter Information")
    for param in params:
        logger.info("Paramter ordinal {} storage {} varnode {}".format(
                param.getOrdinal(), param.getVariableStorage(),
                param.getFirstStorageVarnode())
            )

    print_pcode_info(containing_func, state, func_end.offset)


if __name__ == "__main__":
    main()
