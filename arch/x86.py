import logging

from .arch_class import Architecture

logger = logging.getLogger(__name__)

class x86(Architecture):
    LANG_DESC = "x86/.*/32/.*"
    base_ptr = "EBP"
    def setup_stack(self, state):
        super(x86, self).setup_stack(state)
        state.registers.store(self.lookup_reg_offset(self.base_ptr),
                self.reg_len, self.INIT_STACK_SIZE)

    def _arch_fake_function_call(self, state, func_addr, return_addr):
        rsp_val = state.registers.load(self.stack_ptr_ofst, self.stack_ptr_size)
        state.ram.store(rsp_val, self.reg_len, return_addr)
        state.registers.store(self.pc_offset, self.reg_len, func_addr)

    def co_swi(self, state, callother_index, param):
        raise RuntimeError("Called swi, not implemented!")

    # This definition must come after the functions are defined...
    callother_dict = {
            0xc: co_swi,
            }
