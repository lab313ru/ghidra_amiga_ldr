package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class Library implements StructConverter {
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("Library", 0);
		
		s.add((new Node()).toDataType(), "lib_Node", null);
		s.add(BYTE, "lib_Flags", null);
		s.add(BYTE, "lib_pad", null);
		s.add(WORD, "lib_NegSize", null);
		s.add(WORD, "lib_PosSize", null);
		s.add(WORD, "lib_Version", null);
		s.add(WORD, "lib_Revision", null);
		s.add(new PointerDataType(ASCII), "lib_IdString", null);
		s.add(DWORD, "lib_Sum", null);
		s.add(WORD, "lib_OpenCnt", null);
		
		return s;
	}
}
