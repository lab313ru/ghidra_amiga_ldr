package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class Node implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("Node", 0);
		
		s.add(new PointerDataType(s), "ln_Succ", null);
		s.add(new PointerDataType(s), "ln_Pred", null);
		s.add(BYTE, "ln_Type", null);
		s.add(BYTE, "ln_Pri", null);
		s.add(new PointerDataType(ASCII), "ln_Name", null);
		
		return s;
	}

}
