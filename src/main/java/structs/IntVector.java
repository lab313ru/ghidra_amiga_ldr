package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class IntVector implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("IntVector", 0);
		
		s.add(POINTER, "iv_Data", null);
		s.add(POINTER, "iv_Code", null);
		s.add(new PointerDataType((new Node()).toDataType()), "iv_Node", null);
		
		return s;
	}

}
