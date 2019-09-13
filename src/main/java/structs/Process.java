package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class Process implements StructConverter {

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("Process", 0);

		s.add((new Task()).toDataType(), "pr_Task", null);
		s.add((new MsgPort()).toDataType(), "pr_MsgPort", null);
		s.add(WORD, "pr_Pad", null);
		s.add(new PointerDataType(BYTE), "pr_SegList", null);
		s.add(DWORD, "pr_StackSize", null);
		s.add(POINTER, "pr_GlobVec", null);
		s.add(DWORD, "pr_TaskNum", null);
		s.add(new PointerDataType(BYTE), "pr_StackBase", null);
		s.add(DWORD, "pr_Result2", null);
		s.add(new PointerDataType((new FileLock()).toDataType()), "pr_CurrentDir", null);
		s.add(new PointerDataType((new FileHandle()).toDataType()), "pr_CIS", null);
		s.add(new PointerDataType((new FileHandle()).toDataType()), "pr_COS", null);
		s.add(POINTER, "pr_ConsoleTask", null);
		s.add(POINTER, "pr_FileSystemTask", null);
		s.add(new PointerDataType((new CLI()).toDataType()), "pr_CLI", null);
		s.add(POINTER, "pr_ReturnAddr", null);
		s.add(POINTER, "pr_PktWait", null);
		s.add(POINTER, "pr_WindowPtr", null);
		s.add(new PointerDataType((new FileLock()).toDataType()), "pr_HomeDir", null);
		s.add(DWORD, "pr_Flags", null);
		s.add(POINTER, "pr_ExitCode", null);
		s.add(DWORD, "pr_ExitData", null);
		s.add(new PointerDataType(BYTE), "pr_Arguments", null);
		s.add((new MinList()).toDataType(), "pr_LocalVars", null);
		s.add(DWORD, "pr_ShellPrivate", null);
		s.add(new PointerDataType((new FileHandle()).toDataType()), "pr_CES", null);
		
		return s;
	}

}
