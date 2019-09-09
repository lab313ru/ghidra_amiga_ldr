package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class InitTable implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("InitTable", 0);
		
		s.add(DWORD, "it_DataSize", "library data space size");
		s.add(POINTER, "it_FuncTable", "table of entry points");
		s.add(POINTER, "it_DataInit", "table of data initializers");
		s.add(POINTER, "it_InitFunc", "initialization function to run");
		
		return s;
	}

}
