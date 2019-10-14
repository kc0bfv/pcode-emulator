from collections import defaultdict
import logging

from ghidra.program.model.mem import MemoryAccessException

from .instr import instruction_finder
from .arch import LE, BE

logger = logging.getLogger(__name__)

class InvalidAddrException(Exception):
    pass

class NotCodeException(Exception):
    pass

class InvalidRegException(Exception):
    pass

class CodeWord(list):
    """
    This class represents a memory location containing code.  It will
    store a set of PCODE instruction classes.

    Note that this implementation leads to a serious deficiency - code and
    data are not interchangable here!  For instance - if code is
    self-modifying then the modified result will not be interpreted as code
    by the emulator, and the emulator will die when it tries to execute
    that (see Ram's get_code for that...).  Of course - in order to interpret
    self-modifying code, we also need a way to turn that code into PCODE,
    which is beyond the scope of this software, therefore, this serious
    deficiency is reasonable.
    """
    pass

class MemChunk(defaultdict):
    """
    This is intended to be an implementation of both reg and ram
    """
    def __init__(self, api_base, arch):
        super(MemChunk, self).__init__(int)

        self.arch = arch
        self.api_base = api_base

    def _validate_code(self, addr):
        addr = hex(addr)
        if addr.endswith("L"):
            addr = addr[:-1]
        return self.api_base.getInstructionAt(
                self.api_base.toAddr(addr)) is not None

    def _validate_writeable(self, addr):
        # TODO: check for actual writeableness, maybe
        return not self._validate_code(addr)

    def store(self, address, length, value):
        """Store a value at the given address, of "length" bytes, specified
        endianness (mem.BE or mem.LE).

        TODO param defines
        """
        if not self._validate_writeable(address):
            raise InvalidAddrException("Tried write at non-writeable spot")

        address = long(address)
        value = long(value)

        # Note that python handles bitwise operation on negative numbers as
        # 2s complement and like there are an infinite number of 1's in
        # front of the most significant bit.

        # This means that the below operations are already sign extended,
        # and this is what we'd expect a processor to do.

        # Thus - negative numbers just work.
        cur_val = value
        for ind in range(length):
            if self.arch.endian is LE:
                st_loc = address + ind
            else:
                st_loc = address + ((length - 1) - ind)
            self[st_loc] = cur_val & (2**self.arch.bits_per_byte - 1)
            cur_val >>= self.arch.bits_per_byte

    def load(self, address, length):
        """
        Load a value from the given address, of "length" bytes, specified
        endianness (mem.BE or mem.LE)
        """
        address = long(address)

        cur_val = 0
        for ind in range(length):
            if self.arch.endian is LE:
                st_loc = address + ind
            else:
                st_loc = address + ((length - 1) - ind)
            if st_loc in self:
                cur_val += self[st_loc] << (ind * self.arch.bits_per_byte)
            else:
                try:
                    cur_val += self.api_base.getByte(
                            self.api_base.toAddr(address + ind)
                        ) << (ind * self.arch.bits_per_byte)
                except MemoryAccessException as e:
                #except None as e:
                    cur_val += 0 << (ind * self.arch.bits_per_byte)
        return long(cur_val)

    def __str__(self):
        sorted_keys = sorted(self.keys())
        return ", ".join("0x{:x}: {}".format(key, self[key]) for key in sorted_keys)

class Registers(MemChunk):
    def _validate_writeable(self, addr):
        # This assumes that Ghidra will only try to write to writeable
        # registers.
        return True

class Uniques(Registers):
    pass

class Ram(MemChunk):
    def get_code(self, address):
        if not self._validate_code(address):
            raise InvalidAddrException("No code at address")

        inst = self.api_base.getInstructionAt(self.api_base.toAddr(address))
        inst_size = inst.length
        pcodes = inst.getPcode()
        
        instrs = [instruction_finder(pcode, self.arch) for pcode in pcodes]

        return instrs, inst_size
