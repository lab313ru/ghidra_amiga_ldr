package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WBArg implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("WBArg", 0);
		
		s.add(new PointerDataType(BYTE), "wa_Lock", null);
		s.add(new PointerDataType(BYTE), "wa_Name", null);
		
		return s;
	}

}
