package amigahunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class AmigaLibrary implements StructConverter {
	
	private final FdFunctionTable tbl;
	private final String name;
	private final Program program;
	private final MessageLog log;
	
	public AmigaLibrary(String name, FdFunctionTable tbl, Program program, MessageLog log) {
		this.name = name;
		this.tbl = tbl;
		this.program = program;
		this.log = log;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure s = new StructureDataType(name.replace(".library", "") + "Lib", 0x1002);
		
		Integer[] biases = tbl.getBiases();
		Arrays.sort(biases);
		
		List<Integer> biasesList = new ArrayList<>(Arrays.asList(biases));

		biasesList.add(0);
		
		HashMap<Integer, Integer> sizes = new HashMap<>();
		
		for (int i = 0; i < biasesList.size() - 1; ++i) {
			int bias = biasesList.get(i);
			sizes.put(bias, -1 * (bias - biasesList.get(i + 1)));
		}
		
		for (int i = 0; i < biasesList.size() - 1; ++i) {
			int bias = biasesList.get(i);
			int size = sizes.get(bias);
			FdFunction func = tbl.getFunctionByBias(bias);
			s.replaceAtOffset(bias & 0x3FF, new ArrayDataType(BYTE, size, BYTE.getLength()), size, func.getName(false), null);
			
//			try {
//				VariableStorage vs = new VariableStorage(program, func.getArgRegs(program));
//				FunctionDefinitionDataType fdt = new FunctionDefinitionDataType(sig);
//			} catch (InvalidInputException e) {
//				log.appendException(e);
//			}
		}
		
		return s;
	}
}
