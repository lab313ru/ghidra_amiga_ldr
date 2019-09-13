package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class Message implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("Message", 0);
		
		s.add((new Node()).toDataType(), "mn_Node", null);
		s.add(new PointerDataType((new MsgPort()).toDataType()), "mn_ReplyPort", null);
		s.add(WORD, "mn_Length", null);
		
		return s;
	}

}
