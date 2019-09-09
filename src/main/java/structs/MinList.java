package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class MinList implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("MinList", 0);
		
		s.add(new PointerDataType((new MinNode()).toDataType()), "mlh_Head", null);
		s.add(new PointerDataType((new MinNode()).toDataType()), "mlh_Tail", null);
		s.add(new PointerDataType((new MinNode()).toDataType()), "mlh_TailPred", null);
		
		return s;
	}

}
