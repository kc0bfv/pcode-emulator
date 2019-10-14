#Prints information about pcode.  Click on a function in the decompiler window, run this.
#@author Karl Sickendick kc0bfv@gmail.com
#@category PCode
#@keybinding 
#@menupath 
#@toolbar 


from __future__ import print_function

import logging

from ghidra_pcode_interpreter.mem import NewRam, NewReg, NewUnique, RegModel_x64

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

# TODO Determine these dynamically
ARCH = RegModel_x64 

def get_parameters(func):
    def get_param_val(param):
        print("Param {} - type {}".format(param.getName(), param.getDataType()))
        return askBytes("Parameter Entry",
                "Specify bytes for parameter {} type {}".format(
                    param.getName(), param.getDataType()
                    )
                )


    params = func.getParameters()
    if len(params) == 0:
        print("No parameters - did you commit the locals/params for the func?")

    return [get_param_val(param) for param in params]

def get_func_extents(func):
    addr_set = func.getBody()
    min_addr, max_addr = addr_set.getMinAddress(), addr_set.getMaxAddress()
    return min_addr, max_addr

def run_pcode(func, registers, ram):
    pythonobj = getInstructionAt.__self__

    start_point, func_end = get_func_extents(func)
    logger.info("Func body {} - {}".format(start_point, func_end))

    registers.store(ARCH.pcreg, ARCH.reg_len, start_point.offset)

    keep_going = True
    while keep_going:
        if registers.load(ARCH.pcreg, ARCH.reg_len) == func_end.offset:
            keep_going = False

        cur_loc = registers.load(ARCH.pcreg, ARCH.reg_len)
        logging.debug("Current location: 0x{:x}".format(cur_loc))

        instrs, instr_size = ram.get_code(cur_loc)

        # Update the prog counter
        registers.store(ARCH.pcreg, ARCH.reg_len, 
                registers.load(ARCH.pcreg, ARCH.reg_len) + instr_size
                )

        #uniques = NewUnique(reg_model = ARCH, pythonobj = pythonobj)
        for instr in instrs:
            logger.info("Instruction {}".format(instr))
            logger.info(type(instr.pcode.inputs[0]))
            #instr.execute(registers, ram, uniques)

        #logging.debug("Ram: {}".format(ram))
        #logging.debug("Reg: {}".format(registers))
        #logging.debug("Uniques: {}".format(uniques))

def main():
    pythonobj = getInstructionAt.__self__

    try:
        containing_func = getFunctionContaining(currentLocation.address)
    except:
        logger.error("Could not get containing function for selection")
        exit(1)

    params = containing_func.getParameters()
    logger.info("Parameter Information")
    for param in params:
        logger.info("Paramter ordinal {} storage {} varnode {}".format(
                param.getOrdinal(), param.getVariableStorage(),
                param.getFirstStorageVarnode())
            )

    # TODO: Do memory/register setup
    registers = NewReg(reg_model = ARCH, pythonobj = pythonobj)
    ram = NewRam(pythonobj)

    run_pcode(containing_func, registers, ram)


if __name__ == "__main__":
    main()
