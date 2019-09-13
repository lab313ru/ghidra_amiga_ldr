package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class ExecLibrary implements StructConverter {
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType("ExecLib", 0);

		s.add((new Library()).toDataType(), "LibNode", null);
		s.add(WORD, "SoftVer", null);
		s.add(WORD, "LowMemChkSum", null);
		s.add(DWORD, "ChkBase", null);
		s.add(POINTER, "ColdCapture", null);
		s.add(POINTER, "CoolCapture", null);
		s.add(POINTER, "WarmCapture", null);
		s.add(POINTER, "SysStkUpper", null);
		s.add(POINTER, "SysStkLower", null);
		s.add(DWORD, "MaxLocMem", null);
		s.add(POINTER, "DebugEntry", null);
		s.add(POINTER, "DebugData", null);
		s.add(POINTER, "AlertData", null);
		s.add(POINTER, "MaxExtMem", null);
		s.add(WORD, "ChkSum", null);
		DataType intVector = (new IntVector()).toDataType();
		s.add(new ArrayDataType(intVector, 16, intVector.getLength()), "IntVects", null);
		s.add(new PointerDataType((new Process()).toDataType()), "ThisTask", null);
		s.add(DWORD, "IdleCount", null);
		s.add(DWORD, "DispCount", null);
		s.add(WORD, "Quantum", null);
		s.add(WORD, "Elapsed", null);
		s.add(WORD, "SysFlags", null);
		s.add(BYTE, "IDNestCnt", null);
		s.add(BYTE, "TDNestCnt", null);
		s.add(WORD, "AttnFlags", null);
		s.add(WORD, "AttnResched", null);
		s.add(POINTER, "ResModules", null);
		s.add(POINTER, "TaskTrapCode", null);
		s.add(POINTER, "TaskExceptCode", null);
		s.add(POINTER, "TaskExitCode", null);
		s.add(DWORD, "TaskSigAlloc", null);
		s.add(WORD, "TaskTrapAlloc", null);
		s.add((new List()).toDataType(), "MemList", null);
		s.add((new List()).toDataType(), "ResourceList", null);
		s.add((new List()).toDataType(), "DeviceList", null);
		s.add((new List()).toDataType(), "IntrList", null);
		s.add((new List()).toDataType(), "LibList", null);
		s.add((new List()).toDataType(), "PortList", null);
		s.add((new List()).toDataType(), "TaskReady", null);
		s.add((new List()).toDataType(), "TaskWait", null);
		DataType softIntList = (new SoftIntList()).toDataType();
		s.add(new ArrayDataType(softIntList, 5, softIntList.getLength()), "SoftIntList", null);
		s.add(new ArrayDataType(DWORD, 4, DWORD.getLength()), "LastAlert", null);
		s.add(BYTE, "VBlankFrequency", null);
		s.add(BYTE, "PowerSupplyFrequency", null);
		s.add((new List()).toDataType(), "SemaphoreList", null);
		s.add(POINTER, "KickMemPtr", null);
		s.add(POINTER, "KickTagPtr", null);
		s.add(POINTER, "KickCheckSum", null);
		s.add(DWORD, "ex_Pad0", null);
		s.add(DWORD, "ex_LaunchPoint", null);
		s.add(POINTER, "ex_RamLibPrivate", null);
		s.add(DWORD, "ex_EClockFrequency", null);
		s.add(DWORD, "ex_CacheControl", null);
		s.add(DWORD, "ex_TaskID", null);
		s.add(new ArrayDataType(DWORD, 5, DWORD.getLength()), "ex_Reserved1", null);
		s.add(POINTER, "ex_MMULock", null);
		s.add(new ArrayDataType(DWORD, 3, DWORD.getLength()), "ex_Reserved2", null);
		s.add((new MinList()).toDataType(), "ex_MemHandlers", null);
		s.add(POINTER, "ex_MemHandler", null);
		
		return s;
	}

}
