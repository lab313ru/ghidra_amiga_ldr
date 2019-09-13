package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class FileHandle implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("FileHandle", 0);
		
		s.add(POINTER, "fh_Link", null);
		s.add(POINTER, "fh_Port", null);
		s.add(POINTER, "fh_Type", null);
		s.add(DWORD, "fh_Buf", null);
		s.add(DWORD, "fh_Pos", null);
		s.add(DWORD, "fh_End", null);
		s.add(DWORD, "fh_Funcs", null);
		s.add(DWORD, "fh_Func2", null);
		s.add(DWORD, "fh_Func3", null);
		s.add(DWORD, "fh_Args", null);
		s.add(DWORD, "fh_Arg2", null);
		
		return s;
	}

}
