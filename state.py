import logging

from .mem import Ram, Registers, Uniques
from .arch import instantiate_architecture

logger = logging.getLogger(__name__)

class State(object):
    def __init__(self, api_base):
        self.api_base = api_base
        self.arch = instantiate_architecture(self.api_base)
        if self.arch is None:
            raise RuntimeError("No supported architectures found")

        self.registers = Registers(self.api_base, self.arch)
        self.ram = Ram(self.api_base, self.arch)
        self.uniques = None

    def execute_cur_location(self):
        self.uniques = Uniques(self.api_base, self.arch)

        # Get the instructions and instruction size
        instrs, instr_size = self.ram.get_code(self.get_pc())

        # Step the prog counter before any branches might update it
        self.step_pc()

        # Execute each instruction
        for instr in instrs:
            logger.debug("Executing {}".format(instr))
            instr.execute(self)

        return self.get_pc()


    def __str__(self):
        return "Registers {}\nRam {}\nUniques {}".format(self.registers,
                self.ram, self.uniques)

    def get_pc(self):
        return self.registers.load(self.arch.pc_offset, self.arch.reg_len)

    def set_pc(self, location):
        self.registers.store(self.arch.pc_offset, self.arch.reg_len, location)

    def step_pc(self):
        cur_loc = self.get_pc()
        _, instr_size = self.ram.get_code(cur_loc)
        self.set_pc(cur_loc + instr_size)

    def set_varnode(self, varnode, value):
        if varnode.isRegister():
            self.registers.store(varnode.offset, varnode.size, value)
        elif varnode.isUnique():
            self.uniques.store(varnode.offset, varnode.size, value)
        elif varnode.isAddress():
            self.ram.store(varnode.offset, varnode.size, value)
        elif varnode.getAddress().isStackAddress():
            addr = self.arch.resolve_stack_address(self, varnode.offset)
            self.ram.store(addr, varnode.size, value)
        else:
            raise RuntimeError("Invalid varnode for setting: {}"
                    "".format(varnode))

    def read_varnode(self, varnode):
        if varnode.isRegister():
            return self.registers.load(varnode.offset, varnode.size)
        elif varnode.isUnique():
            return self.uniques.load(varnode.offset, varnode.size)
        elif varnode.isAddress():
            return self.ram.load(varnode.offset, varnode.size)
        elif varnode.isConstant():
            return varnode.offset
        elif varnode.getAddress().isStackAddress():
            addr = self.arch.resolve_stack_address(self, varnode.offset)
            return self.ram.load(addr, varnode.size)
        else:
            raise RuntimeError("Unknown varnode type: {}".format(varnode))

    def setup_stack(self):
        self.arch.setup_stack(self)

    def fake_function_call(self, func_addr):
        self.arch.fake_function_call(self, func_addr)
