package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class FileLock implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("FileLock", 0);
		
		s.add(new PointerDataType(s), "fl_Link", null);
		s.add(DWORD, "fl_Key", null);
		s.add(DWORD, "fl_Access", null);
		s.add(POINTER, "fl_Task", null);
		s.add(new PointerDataType(BYTE), "fl_Volume", null);
		
		return s;
	}

}
