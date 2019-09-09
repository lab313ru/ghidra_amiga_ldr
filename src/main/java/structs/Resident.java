package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class Resident implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("Resident", 0);
		
		s.add(WORD, "rt_MatchWord", "word to match on (ILLEGAL)");
		s.add(new PointerDataType(s), "rt_MatchTag", "pointer to the above");
		s.add(POINTER, "rt_EndSkip", "address to continue scan");
		s.add(BYTE, "rt_Flags", "various tag flags");
		s.add(BYTE, "rt_Version", "release version number");
		s.add(BYTE, "rt_Type", "type of module (NT_XXXXXX)");
		s.add(BYTE, "rt_Pri", "initialization priority");
		s.add(new PointerDataType(STRING), "rt_Name", "pointer to node name");
		s.add(new PointerDataType(STRING), "rt_IdString", "pointer to identification string");
		s.add(POINTER, "rt_Init", "pointer to init code");
		
		return s;
	}

}
