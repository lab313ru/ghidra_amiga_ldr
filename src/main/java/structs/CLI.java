package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class CLI implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("CLI", 0);
		
		s.add(DWORD, "cli_Result2", null);
		s.add(new PointerDataType(ASCII), "cli_SetName", null);
		s.add(new PointerDataType((new PathList()).toDataType()), "cli_CommandDir", null);
		s.add(DWORD, "cli_ReturnCode", null);
		s.add(new PointerDataType(ASCII), "cli_CommandName", null);
		s.add(DWORD, "cli_FailLevel", null);
		s.add(new PointerDataType(ASCII), "cli_Prompt", null);
		s.add(new PointerDataType((new FileHandle()).toDataType()), "cli_StandardInput", null);
		s.add(new PointerDataType((new FileHandle()).toDataType()), "cli_CurrentInput", null);
		s.add(new PointerDataType(ASCII), "cli_CommandFile", null);
		s.add(DWORD, "cli_Interactive", null);
		s.add(DWORD, "cli_Background", null);
		s.add(new PointerDataType((new FileHandle()).toDataType()), "cli_CurrentOutput", null);
		s.add(DWORD, "cli_DefaultStack", null);
		s.add(new PointerDataType((new FileHandle()).toDataType()), "cli_StandardOutput", null);
		s.add(new PointerDataType(BYTE), "cli_Module", null);
		
		return s;
	}

}
