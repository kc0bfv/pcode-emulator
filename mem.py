from collections import defaultdict
import logging

from ghidra.program.model.mem import MemoryAccessException

from .instr import instruction_finder
from .arch import LE, BE
from .mem_markers import UniqueMarker

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
        """Store a value at the given address, of "length" bytes, with
        endianness matching the architecture

        :param address: The index at which to store value
        :type addres: int
        :param length: The number of bytes over which to store value
        :type length: int
        :param value: The value to store
        :type value: int

        :raises InvalidAddrException: When the address was not writeable
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

    def load_byte(self, address):
        """Load just one byte from address
        """
        return self[address]

    def load(self, address, length):
        """Load a value from the given address, of "length" bytes, with
        endianness matching the architecture.

        :param address: The index from which to load
        :type addres: int
        :param length: The number of bytes to load
        :type length: int

        :return: The value loaded
        :rtype: int
        """
        address = long(address)

        cur_val = 0
        for ind in range(length):
            if self.arch.endian is LE:
                st_loc = address + ind
            else:
                st_loc = address + ((length - 1) - ind)
            one_byte = self.load_byte(st_loc) % 256
            cur_val += one_byte << (ind * self.arch.bits_per_byte)
        return long(cur_val)

    def __str__(self):
        sorted_keys = sorted(self.keys())
        return ", ".join("0x{:x}: {}".format(key, hex(self[key])) for key in sorted_keys)

class Registers(MemChunk):
    def _validate_writeable(self, addr):
        # This assumes that Ghidra will only try to write to writeable
        # registers.
        return True

    def __str__(self):
        def fmt_key(key):
            reg = None
            try:
                # Get the register object if possible
                reg = self.arch.lookup_reg_by_offset(key)
            except IndexError as e:
                logging.debug("Register not found {} {}".format(key, e))

            reg_size = 1
            reg_name = key
            if reg is not None:
                reg_size = reg.getMinimumByteSize()
                reg_name = "{}({:x})".format(reg.name, key)
            out_txt = "{}: 0x{:x}".format(reg_name, self.load(key, reg_size))
            used_keys = set(range(key, key + reg_size))
            return out_txt, used_keys
        sorted_keys = sorted(self.keys())
        vals = list()
        all_used_keys = set()
        for key in sorted_keys:
            if key in all_used_keys:
                continue
            out_txt, used_keys = fmt_key(key)
            all_used_keys = all_used_keys.union(used_keys)
            vals.append(out_txt)
        return ", ".join(vals)

class Uniques(MemChunk):
    def _validate_writeable(self, addr):
        # This assumes that Ghidra will only try to write to writeable
        # uniques.
        return True

    def store(self, address, length, value):
        """Store a value just like for the parent class, however, if
        the value is a UniqueMarker instance, store it as a special case 
        at only the address.
        """
        if isinstance(value, UniqueMarker):
            self[address] = value
        else:
            super(Uniques, self).store(address, length, value)
    def load(self, address, length):
        """Load a value just like for the parent class, however, if
        the value is a UniqueMarker instance return only it.
        """
        if isinstance(self[address], UniqueMarker):
            return self[address]
        else:
            return super(Uniques, self).load(address, length)

class Ram(MemChunk):
    def load_byte(self, address):
        if address in self:
            return self[address]
        else:
            try:
                # It handles 64 bit values better when they're hex strings
                # without an L at the end
                addr = self.api_base.toAddr(hex(long(address))[:-1])
                return self.api_base.getByte(addr)
            except MemoryAccessException as e:
                logger.debug("mem access except")
                return 0

    def get_code(self, address):
        if not self._validate_code(address):
            raise InvalidAddrException("No code at address")

        inst = self.api_base.getInstructionAt(self.api_base.toAddr(address))
        inst_size = inst.length
        pcodes = inst.getPcode()
        
        instrs = [instruction_finder(pcode, self.arch) for pcode in pcodes]

        return instrs, inst_size
