package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WBStartup implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("WBStartup", 0);
		
		s.add((new Message()).toDataType(), "sm_Message", null);
		s.add(new PointerDataType((new MsgPort()).toDataType()), "sm_Process", null);
		s.add(new PointerDataType(BYTE), "sm_Segment", null);
		s.add(DWORD, "sm_NumArgs", null);
		s.add(new PointerDataType(ASCII), "sm_ToolWindow", null);
		s.add(new PointerDataType((new WBArg()).toDataType()), "sm_ArgList", null);
		
		return s;
	}

}
