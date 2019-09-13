package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class MsgPort implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("MsgPort", 0);

		s.add((new Node()).toDataType(), "mp_Node", null);
		s.add(BYTE, "mp_Flags", null);
		s.add(BYTE, "mp_SigBit", null);
		s.add(POINTER, "mp_SigTask", null);
		s.add((new List()).toDataType(), "mp_MsgList", null);
		
		return s;
	}

}
