import logging

from .arch_class import Architecture

logger = logging.getLogger(__name__)

class ARM(Architecture):
    LANG_DESC = "ARM/.*/.*/.*"
    link_reg = "lr"
    def _arch_fake_function_call(self, state, func_addr, return_addr):
        # Setup LR and pcreg
        state.registers.store(self.lookup_reg_offset(self.link_reg),
                self.reg_len, return_addr)
        state.registers.store(self.pc_offset, self.reg_len, func_addr)

    # Must come after the functions are defined...
    callother_dict = {
            }
