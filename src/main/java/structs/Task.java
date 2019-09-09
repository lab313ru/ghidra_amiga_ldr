package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class Task implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("Task", 0);
		
		s.add((new Node()).toDataType(), "tc_Node", null);
		s.add(BYTE, "tc_Flags", null);
		s.add(BYTE, "tc_State", null);
		s.add(BYTE, "tc_IDNestCnt", null);
		s.add(BYTE, "tc_TDNestCnt", null);
		s.add(DWORD, "tc_SigAlloc", null);
		s.add(DWORD, "tc_SigWait", null);
		s.add(DWORD, "tc_SigRecvd", null);
		s.add(DWORD, "tc_SigExcept", null);
		s.add(WORD, "tc_TrapAlloc", null);
		s.add(WORD, "tc_TrapAble", null);
		s.add(POINTER, "tc_ExceptData", null);
		s.add(POINTER, "tc_ExceptCode", null);
		s.add(POINTER, "tc_TrapData", null);
		s.add(POINTER, "tc_TrapCode", null);
		s.add(POINTER, "tc_SPReg", null);
		s.add(POINTER, "tc_SPLower", null);
		s.add(POINTER, "tc_SPUpper", null);
		s.add(POINTER, "tc_Switch", null);
		s.add(POINTER, "tc_Launch", null);
		s.add((new List()).toDataType(), "tc_MemEntry", null);
		s.add(POINTER, "tc_UserData", null);
		
		return s;
	}

}
