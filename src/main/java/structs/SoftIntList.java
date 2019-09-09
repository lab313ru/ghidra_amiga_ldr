package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class SoftIntList implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("SoftIntList", 0);
		
		s.add((new List()).toDataType(), "sh_List", null);
		s.add(WORD, "sh_Pad", null);
		
		return s;
	}

}
