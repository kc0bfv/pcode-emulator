import logging
import re
import types

from ghidra.program.util import VarnodeContext

from ..utils import find_all_subclasses, get_api_base

logger = logging.getLogger(__name__)

LE = "LittleEndian"
BE = "BigEndian"

class Architecture(object):
    # Set LANG_DESC to the language description in Ghidra appropriate to
    # the architecture in question.
    LANG_DESC = None
    # Set callother_dict in subclasses to associate callother function
    # implementations with a callother index
    callother_dict = None

    INIT_STACK_SIZE = 0x100000
    reg_offset_lookedup = list()

    def __init__(self, api_base):
        self.api_base = api_base

        # Determine settings of the current architecture
        self.cur_prog = self.api_base.getCurrentProgram()
        self.lang = self.cur_prog.getLanguage()
        self.lang_desc = self.lang.getLanguageDescription()

        # Processor properties
        self.proc = self.lang_desc.getProcessor()
        self.proc_size = self.lang_desc.getSize()

        # Properties of the program counter
        self.pc = self.lang.getProgramCounter()
        self.pc_offset = self.pc.getOffset()
        self.pc_byte_size = self.pc.getMinimumByteSize()
        self.pc_bit_count = self.pc.getBitLength()
        self.pc_bits_per_byte = self.pc_bit_count // self.pc_byte_size

        # Register properties
        self.endian = BE if self.lang.isBigEndian() else LE
        self.reg_len = self.pc_byte_size
        self.bits_per_byte = self.pc_bits_per_byte

        # This address stands in as a return address for the original function
        # call.  Therefore - it should be a return address that will never 
        # appear during legitimate program execution.  That may be
        # architecture dependent...
        self.sentinel_return_addr = 0xff * self.reg_len

        # Determine how the stack is recorded
        self.varnode_context = VarnodeContext(
                self.cur_prog,
                self.cur_prog.getProgramContext(),
                self.cur_prog.getProgramContext())
        self.stack_varnode = self.varnode_context.getStackVarnode()
        self.stack_ptr_ofst = self.stack_varnode.offset
        self.stack_ptr_size = self.stack_varnode.size

    def lookup_reg_offset(self, reg_name):
        """Lookup Ghidra's offset for a register.

        :param reg_name: The register name to lookup
        :type reg_name: string

        :raises RuntimeError: When an invalid register name is provided
        
        :return: The offset of the register in the registers space
        :rtype: int
        """
        try:
            return self.lang.getRegister(reg_name).getOffset()
        except AttributeError as e:
            raise RuntimeError("Invalid register name {}".format(reg_name))

    def lookup_reg_by_offset(self, offset):
        """Lookup the matching register name based on Ghidra's offset

        :param offset: The register offset to lookup
        :type offset: int

        :raises IndexError: When the offset was not valid for registers

        :return: The register name corresponding to offset
        :rtype: string
        """
        if offset not in self.reg_offset_lookedup:
            # Multiple regs might have the same offset, e.g. EIP and RIP
            matching_regs = [reg for reg in self.lang.getRegisters()
                    if reg.getOffset() == offset]
            # We want to return the highest parent reg that has same offset
            best_match = matching_regs[0]
            next_try = best_match.getParentRegister()
            while next_try is not None and next_try.getOffset() == offset:
                best_match = next_try
                next_try = best_match.getParentRegister()
            self.reg_offset_lookedup[offset] = best_match.name

        return self.reg_offset_lookedup[offset]

    def return_callother_names(self):
        """Return a list of callother operation names for the architecture.
        This is more a way of learning about Ghidra, which has an internal
        list of these, with each name corresponding to an index.  The indexes
        of the names in the list this function returns will correspond with
        the indexes in Ghidra.

        :return: List of callother names, ordered/indexed same as in Ghidra
        :rtype: list
        """
        udopcnt = self.lang.getNumberOfUserDefinedOpNames()
        return [self.lang.getUserDefinedOpName(ind) for ind in range(udopcnt)]
        
    def setup_stack(self, state):
        """Setup the stack registers as necessary.

        The base class version only sets the stack pointer.
        """
        state.registers.store(self.stack_ptr_ofst,
                self.stack_ptr_size, self.INIT_STACK_SIZE)

    def fake_function_call(self, state, func_addr, return_addr = None):
        """Setup the stack and registers to fake a function call
        """
        if return_addr is None:
            return_addr = self.sentinel_return_addr
        self._arch_fake_function_call(state, func_addr, return_addr)

    def _arch_fake_function_call(self, state, func_addr, return_addr):
        raise RuntimeError("Called fake_function_call on base class")

    def resolve_stack_address(self, state, stack_offset):
        """Resolve a stack offset into a RAM address.
        """
        base = state.registers.load(self.stack_ptr_ofst, self.stack_ptr_size)
        return base + stack_offset

    def resolve_callother(self, callother_index, param):
        """Return the callother function that corresponds to callother_index
        and, optionally, param.  This version assumes that the architecture
        subclasses have a dictionary/list called callother_dict with
        indexes as keys and architecture class functions as values.

        :param callother_index: Ghidra's index of the callother
        :type callother_index: int
        :param param: The parameter Ghidra specifies for the callother
        :type param: int

        :raises RuntimeError: When there's no existing callother_index

        :return: The function corresponding to callother_index and param.  The
                function must take as arguments the program state, the
                callother_index, and parameter.  It must return either None or
                the new program counter.  If it returns None, the program
                counter will continue unchanged.
        :rtype: function(State, callother_index, param) -> 
                None or new_program_counter
        """
        if callother_index in self.callother_dict:
            unbound_version = self.callother_dict[callother_index]
            # Bind the unbound version and return
            return types.MethodType(unbound_version, self)
        else:
            raise RuntimeError("No callother implemented for {} {}".format(
                    callother_index, param))
