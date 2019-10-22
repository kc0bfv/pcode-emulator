"""Implements the pcode instructions.

Intended usage is to call "instruction_finder", providing a Ghidra pcode
object.  That will return an appropriate instance of an Instruction object
corresponding to the pcode instruction.  That instance can then have "execute"
run on it.
"""

import logging
import re

from .utils import find_all_subclasses
from .mem_markers import CallOtherMarker

logger = logging.getLogger(__name__)

class Instruction(object):
    """The base class for implementation of PCode instructions.

    Instantiate the proper Instruction object, then run execute, to modify
    emulator state corresponding to instruction execution.

    :param pcode: The ghidra pcode object from which to pull parameter
        information.
    :type pcode: ghidra.program.model.pcode.PcodeOp
    :param arch: The architecture for the instruction
    :type arch: Architecture
    """
    
    opcode = None
    def __init__(self, pcode, arch):
        """Constructor
        """
        self.pcode = pcode
        self.arch = arch

    def execute(self, state):
        """Execute an opcode and set emulator state as necessary.
        """
        inputs = self._resolve_inputs(state)
        ret = self._simple_exec_handler(state, inputs)
        if ret is not None:
            self._store_in_output(state, ret)

    def _simple_exec_handler(self, state, inputs):
        """A simpler version of execution handler for implementation.

        :param inputs: A list of input values for the pcode
        :type inputs: list

        :raises RuntimeError: When called on an instance of the base class
            instead of a subclass

        :return: The output value from the pcode instruction, for storage
            in the output location
        :rtype: int
        """
        raise RuntimeError("Called _simple_exec_handler on top-most class")

    def __str__(self):
        return "{}: {}".format(self.__class__.__name__, self.pcode)

    def _resolve_inputs(self, state):
        return [state.read_varnode(in_op) for in_op in self.pcode.inputs]

    def _store_in_output(self, state, value):
        return state.set_varnode(self.pcode.output, value)

    def _get_sign_bit(self, val, size):
        """Return the sign bit for a given value, for a set size and emulator
        register type.

        :param val: The value to calculate twos complement for
        :type val: int
        :param size: The number of bytes in the result
        :type size: int
        """
        # TODO - better place to pull bit count from?
        end_bits = val >> ((size * self.arch.bits_per_byte) - 1)
        return end_bits & 0x1

    def _get_2s_comp(self, val, size):
        """Return the twos complement of a value, for a set size and emulator
        register type.

        :param val: The value to calculate twos complement for
        :type val: int
        :param size: The number of bytes in the result
        :type size: int
        """
        return ((~val) + 1) & (2 ** (size * self.arch.bits_per_byte) - 1)


class Fill_In_Inst(Instruction):
    opcode = -1
    def _simple_exec_handler(self, state, inputs):
        raise RuntimeError("Tried to run fill-in instruction for opcode {}"
                "".format(self.pcode.opcode))
            
class Copy(Instruction):
    opcode = 1
    def _simple_exec_handler(self, state, inputs):
        return inputs[0]

class Load(Instruction):
    opcode = 2
    def _simple_exec_handler(self, state, inputs):
        return state.ram.load(inputs[1], self.pcode.inputs[1].size)

class Store(Instruction):
    opcode = 3
    def _simple_exec_handler(self, state, inputs):
        state.ram.store(inputs[1], self.pcode.inputs[2].size, inputs[2])
        return None

class Branch(Instruction):
    opcode = 4
    def _simple_exec_handler(self, state, inputs):
        state.registers.store(self.arch.pc_offset, self.arch.reg_len,
                self.pcode.inputs[0].offset)
        return None

class CBranch(Branch):
    opcode = 5
    def _simple_exec_handler(self, state, inputs):
        if inputs[1]:
            return super(CBranch, self)._simple_exec_handler(state, inputs)
        else:
            return None

class BranchInd(Instruction):
    """Indirect branch or call.  Dereference input 0, then jump to the
    result.  Alternatively - if input 0 is an instance of CallOtherMarker,
    that means the program should continue on without interruption.
    """
    opcode = 6
    def _simple_exec_handler(self, state, inputs):
        if not isinstance(inputs[0], CallOtherMarker):
            next_loc = inputs[0]
            state.registers.store(self.arch.pc_offset, self.arch.reg_len,
                    next_loc)
            return None


            next_loc = state.ram.load(inputs[0], self.pcode.inputs[0].size)
            logger.debug("in {} sz {} next {}".format(inputs[0], self.pcode.inputs[0].size, next_loc))
            logger.debug("ins {}".format(self.pcode.inputs))
            state.registers.store(self.arch.pc_offset, self.arch.reg_len,
                    next_loc)
        return None

class Call(Branch):
    opcode = 7

class CallInd(BranchInd):
    opcode = 8

class CallOther(Instruction):
    """CallOther instructions are described in a couple places, and implement a number of operations like software interrupts...  "userop.hh" describes them as below:
        "Within the raw p-code framework, the CALLOTHER opcode represents a user defined operation. At this level, the operation is just a placeholder for inputs and outputs to same black-box procedure. The first input parameter (index 0) must be a constant id associated with the particular procedure. Classes derived off of this base class provide a more specialized definition of an operation/procedure. The specialized classes are managed via UserOpManage and are associated with CALLOTHER ops via the constant id.
        "The derived classes can in principle implement any functionality, tailored to the architecture or program. At this base level, the only commonality is a formal \b name of the operator and its CALLOTHER index.  A facility for reading in implementation details is provided via restoreXml()."
    
    "improvingDisassemblyAndDecompilation.tex" has this to say about them: "These operations show up as CALLOTHER Pcode ops in the Pcode field in the Listing.  They can have inputs and outputs, but otherwise are treated as black boxes by the decompiler."

    In this code, we have to look up the operation in an architecture
    specific way, then execute it.  Our return value needs to be a pointer to
    the next location to execute, because it will get "CallInd" executed
    on it.  Alternatively, CallInd/BranchInd will understand an instance of
    CallOtherMarker being returned, and will simply continue executing code
    without branching, when it is found.
    """
    opcode = 9
    def _simple_exec_handler(self, state, inputs):
        other_op = state.arch.resolve_callother(inputs[0], inputs[1])
        retval = other_op(state, inputs[0], inputs[1])
        return CallOtherMarker() if retval is None else retval
        

class Return(Instruction):
    opcode = 10
    def _simple_exec_handler(self, state, inputs):
        return None

class Int_Equal(Instruction):
    opcode = 11
    def _simple_exec_handler(self, state, inputs):
        return 1 if inputs[0] == inputs[1] else 0

class Int_NotEqual(Instruction):
    opcode = 12
    def _simple_exec_handler(self, state, inputs):
        return 1 if inputs[0] != inputs[1] else 0

class Int_SLess(Instruction):
    opcode = 13
    def _simple_exec_handler(self, state, inputs):
        in0_bit = self._get_sign_bit(inputs[0], self.pcode.inputs[0].size)
        in1_bit = self._get_sign_bit(inputs[1], self.pcode.inputs[1].size)
        # If one is neg and one is pos, then return 1 if in0 is neg
        if in0_bit != in1_bit:
            return 1 if in0_bit == 1 else 0
        # Otherwise, regular inequality will work
        return 1 if inputs[0] < inputs[1] else 0

class Int_SLessEqual(Instruction):
    opcode = 14
    def _simple_exec_handler(self, state, inputs):
        in0_bit = self._get_sign_bit(inputs[0], self.pcode.inputs[0].size)
        in1_bit = self._get_sign_bit(inputs[1], self.pcode.inputs[1].size)
        # If one is neg and one is pos, then return 1 if in0 is neg
        if in0_bit != in1_bit:
            return 1 if in0_bit == 1 else 0
        # Otherwise, regular inequality will work
        return 1 if inputs[0] <= inputs[1] else 0

class Int_Less(Instruction):
    opcode = 15
    def _simple_exec_handler(self, state, inputs):
        return 1 if inputs[0] < inputs[1] else 0

class Int_LessEqual(Instruction):
    opcode = 16
    def _simple_exec_handler(self, state, inputs):
        return 1 if inputs[0] <= inputs[1] else 0

class Int_Zext(Instruction):
    opcode=17
    def _simple_exec_handler(self, state, inputs):
        # Things are already zero extended...
        return inputs[0]

class Int_Sext(Instruction):
    opcode=18
    def _simple_exec_handler(self, state, inputs):
        in0_bit = self._get_sign_bit(inputs[0], self.pcode.inputs[0].size)
        if in0_bit == 0:
            return inputs[0]
        new_len = self.pcode.output.size * self.arch.bits_per_byte
        old_len = self.pcode.inputs[0].size * self.arch.bits_per_byte
        extension = ((2 ** new_len) - 1) ^ ((2 ** old_len) - 1)
        return extension | inputs[0]

class Int_Add(Instruction):
    opcode = 19 
    def _simple_exec_handler(self, state, inputs):
        return inputs[0] + inputs[1]

class Int_Sub(Instruction):
    opcode = 20 
    def _simple_exec_handler(self, state, inputs):
        return inputs[0] - inputs[1]

class Int_Carry(Instruction):
    # This becomes the carry flag in add (matters with unsigned ints)
    opcode = 21 
    
    def _simple_exec_handler(self, state, inputs):
        input_size = self.pcode.inputs[0].size
        add_result = inputs[0] + inputs[1]

        # See if there was a carry by seeing if the add_result had more bits thn
        # could be stored
        # TODO - better place to pull bit count from?
        leftover = add_result >> (input_size * self.arch.bits_per_byte)
        return 1 if leftover > 0 else 0

class Int_SCarry(Instruction):
    # This becomes the overflow flag in add (matters with signed ints)
    opcode = 22
    def _simple_exec_handler(self, state, inputs):
        input_0_carry = self._get_sign_bit(inputs[0], self.pcode.inputs[0].size)
        input_1_carry = self._get_sign_bit(inputs[1], self.pcode.inputs[1].size)

        # Can't have signed overflow if the inputs are of different sign
        if input_0_carry != input_1_carry:
            return 0

        # If they are the same sign, then the result must be too
        add_result = inputs[0] + inputs[1]
        add_result_carry = self._get_sign_bit(add_result,
                self.pcode.inputs[1].size)
        return 0 if input_0_carry == add_result_carry else 1

class Int_SBorrow(Instruction):
    # Becomes the overflow flag in sub (matters with signed ints)
    # SBorrow is used to determine OF flag in x64 sub/cmp
    # It indicates an overflow in the signed result
    # Int_Less determines the CF flag, which is an overflow in the unsigned result
    opcode = 23
    def _simple_exec_handler(self, state, inputs):
        input_0_sign = self._get_sign_bit(inputs[0], self.pcode.inputs[0].size)
        input_1_sign = self._get_sign_bit(inputs[1], self.pcode.inputs[1].size)
        # No signed overflow if inputs are of same sign
        if input_0_sign == input_1_sign:
            return 0

        input_size = self.pcode.inputs[0].size
        sub_result = inputs[0] - inputs[1]

        res_sign = self._get_sign_bit(sub_result, input_size)

        # I believe this is correct now.
        return 1 if res_sign != input_0_sign else 0

class Int_2Comp(Instruction):
    opcode = 24
    def _simple_exec_handler(self, state, inputs):
        # TODO: Is this correct?  I think Python's gonna handle the 
        # negation for me, correctly
        return -inputs[0]

class Int_Negate(Instruction):
    opcode = 25
    def _simple_exec_handler(self, state, inputs):
        return ~inputs[0]

class Int_Xor(Instruction):
    opcode = 26
    def _simple_exec_handler(self, state, inputs):
        return inputs[0] ^ inputs[1]

class Int_And(Instruction):
    opcode = 27
    def _simple_exec_handler(self, state, inputs):
        return inputs[0] & inputs[1]

class Int_Or(Instruction):
    opcode = 28
    def _simple_exec_handler(self, state, inputs):
        return inputs[0] | inputs[1]

class Int_Left(Instruction):
    opcode = 29
    def _simple_exec_handler(self, state, inputs):
        return inputs[0] << inputs[1]

class Int_Right(Instruction):
    opcode = 30
    def _simple_exec_handler(self, state, inputs):
        unsigned_ver = inputs[0]
        if inputs[0] < 0:
            unsigned_ver = self._get_2s_comp(abs(inputs[0]),
                    self.pcode.inputs[0].size)
        return unsigned_ver >> inputs[1]

class Int_SRight(Instruction):
    opcode = 31
    def _simple_exec_handler(self, state, inputs):
        return inputs[0] >> inputs[1]

class Int_Mult(Instruction):
    opcode = 32
    def _simple_exec_handler(self, state, inputs):
        return inputs[0] * inputs[1]

class Int_Div(Instruction):
    opcode = 33
    def _simple_exec_handler(self, state, inputs):
        return inputs[0] // inputs[1]

class Int_SDiv(Instruction):
    opcode = 34
    def _simple_exec_handler(self, state, inputs):
        in_0_bit = self._get_sign_bit(inputs[0], self.pcode.inputs[0].size)
        in_1_bit = self._get_sign_bit(inputs[1], self.pcode.inputs[1].size)
        if in_0_bit == 0 and in_1_bit == 0:
            return inputs[0] // inputs[1]
        elif in_0_bit == 1 and in_1_bit == 1:
            in0_inv = self._get_2s_comp(inputs[0], self.pcode.inputs[0].size)
            in1_inv = self._get_2s_comp(inputs[1], self.pcode.inputs[1].size)
            return in0_inv // in0_inv
        else:
            if in_0_bit == 1:
                in0_pos = self._get_2s_comp(inputs[0],
                        self.pcode.inputs[0].size)
                in1_pos = inputs[1]
            else:
                in0_pos = inputs[0]
                in1_pos = self._get_2s_comp(inputs[1],
                        self.pcode.inputs[1].size)

            res = in0_pos // in1_pos
            return self._get_2s_comp(res, self.pcode.inputs[0].size)

class Int_Rem(Instruction):
    opcode = 35
    def _simple_exec_handler(self, state, inputs):
        return inputs[0] % inputs[1]

class Int_SRem(Instruction):
    opcode = 36
    def _simple_exec_handler(self, state, inputs):
        in_0_bit = self._get_sign_bit(inputs[0], self.pcode.inputs[0].size)
        in_1_bit = self._get_sign_bit(inputs[1], self.pcode.inputs[1].size)
        if in_0_bit == 0 and in_1_bit == 0:
            return inputs[0] % inputs[1]
        elif in_0_bit == 1 and in_1_bit == 1:
            in0_inv = self._get_2s_comp(inputs[0], self.pcode.inputs[0].size)
            in1_inv = self._get_2s_comp(inputs[1], self.pcode.inputs[1].size)
            return in0_inv % in0_inv
        else:
            if in_0_bit == 1:
                in0_pos = self._get_2s_comp(inputs[0],
                        self.pcode.inputs[0].size)
                in1_pos = inputs[1]
            else:
                in0_pos = inputs[0]
                in1_pos = self._get_2s_comp(inputs[1],
                        self.pcode.inputs[1].size)

            res = in0_pos % in1_pos
            return self._get_2s_comp(res, self.pcode.inputs[0].size)

class Bool_Negate(Instruction):
    opcode = 37
    def _simple_exec_handler(self, state, inputs):
        return 1 if inputs[0] == 0 else 0

class Bool_Xor(Instruction):
    opcode = 38
    def _simple_exec_handler(self, state, inputs):
        return 1 if inputs[0] != inputs[1] else 0

class Bool_And(Instruction):
    opcode = 39
    def _simple_exec_handler(self, state, inputs):
        return 1 if inputs[0] and inputs[1] else 0

class Bool_Or(Instruction):
    opcode = 40
    def _simple_exec_handler(self, state, inputs):
        return 1 if inputs[0] or inputs[1] else 0


class Subpiece(Instruction):
    opcode = 63
    def _simple_exec_handler(self, state, inputs):
        return inputs[0] >> (inputs[1] * self.arch.bits_per_byte)

"""
Opcode map
(1, u'COPY')
(2, u'LOAD')
(3, u'STORE')
(4, u'BRANCH')
(5, u'CBRANCH')
(6, u'BRANCHIND')
(7, u'CALL')
(8, u'CALLIND')
(9, u'CALLOTHER')
(10, u'RETURN')
(11, u'INT_EQUAL')
(12, u'INT_NOTEQUAL')
(13, u'INT_SLESS')
(14, u'INT_SLESSEQUAL')
(15, u'INT_LESS')
(16, u'INT_LESSEQUAL')
(17, u'INT_ZEXT')
(18, u'INT_SEXT')
(19, u'INT_ADD')
(20, u'INT_SUB')
(21, u'INT_CARRY')
(22, u'INT_SCARRY')
(23, u'INT_SBORROW')
(24, u'INT_2COMP')
(25, u'INT_NEGATE')
(26, u'INT_XOR')
(27, u'INT_AND')
(28, u'INT_OR')
(29, u'INT_LEFT')
(30, u'INT_RIGHT')
(31, u'INT_SRIGHT')
(32, u'INT_MULT')
(33, u'INT_DIV')
(34, u'INT_SDIV')
(35, u'INT_REM')
(36, u'INT_SREM')
(37, u'BOOL_NEGATE')
(38, u'BOOL_XOR')
(39, u'BOOL_AND')
(40, u'BOOL_OR')
(41, u'FLOAT_EQUAL')
(42, u'FLOAT_NOTEQUAL')
(43, u'FLOAT_LESS')
(44, u'FLOAT_LESSEQUAL')
(45, u'INVALID_OP')
(46, u'FLOAT_NAN')
(47, u'FLOAT_ADD')
(48, u'FLOAT_DIV')
(49, u'FLOAT_MULT')
(50, u'FLOAT_SUB')
(51, u'FLOAT_NEG')
(52, u'FLOAT_ABS')
(53, u'FLOAT_SQRT')
(54, u'INT2FLOAT')
(55, u'FLOAT2FLOAT')
(56, u'TRUNC')
(57, u'CEIL')
(58, u'FLOOR')
(59, u'ROUND')
(60, u'MULTIEQUAL')
(61, u'INDIRECT')
(62, u'PIECE')
(63, u'SUBPIECE')
(64, u'CAST')
(65, u'PTRADD')
(66, u'PTRSUB')
(67, u'INVALID_OP')
(68, u'CPOOLREF')
(69, u'NEW')
"""

def instruction_finder(pcode, arch):
    """Returns the correct instruction class for a given Ghidra pcode object.
    Pcode objects are returned by the "getPcode" function on instruction
    objects.  Instruction objects are returned by the "getInstructionAt"
    function.

    :param pcode: The pcode object for which to find instructions
    :type pcode: ghidra.program.model.pcode.PcodeOp
    :param arch: The architecture for the instruction
    :type arch: Architecture

    :raises RuntimeError: Occurs when multiple implementations are found
        for one pcode.  That indicates an implementation error.

    :return: An instance of one instruction class implementing the pcode
        input.  Returns "Fill_In_Inst" when no matching instruction is found.
    :rtype: Instruction
    """
    opcode = pcode.opcode
    inst_class_matches = [cls
            for cls in find_all_subclasses(Instruction)
            if cls.opcode == opcode]
    if len(inst_class_matches) > 1:
        raise RuntimeError("Found multiple implementations for opcode {}"
                "".format(opcode))
    elif len(inst_class_matches) < 1:
        """
        raise RuntimeError("Found no implementation for opcode {}"
                "".format(opcode))
        """
        return Fill_In_Inst(pcode, arch)
    return inst_class_matches[0](pcode, arch)
