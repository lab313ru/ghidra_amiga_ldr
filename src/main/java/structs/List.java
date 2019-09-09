package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class List implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("List", 0);
		
		s.add(new PointerDataType((new Node()).toDataType()), "lh_Head", null);
		s.add(new PointerDataType((new Node()).toDataType()), "lh_Tail", null);
		s.add(new PointerDataType((new Node()).toDataType()), "lh_TailPred", null);
		s.add(BYTE, "lh_Type", null);
		s.add(BYTE, "l_pad", null);
		
		return s;
	}

}
