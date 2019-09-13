package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class PathList implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("PathList", 0);
		
		s.add(new PointerDataType(s), "lp_Next", null);
		s.add(new PointerDataType((new FileLock()).toDataType()), "lp_Lock", null);
		
		return s;
	}

}
