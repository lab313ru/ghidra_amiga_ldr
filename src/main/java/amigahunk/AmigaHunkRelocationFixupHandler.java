package amigahunk;

import ghidra.app.plugin.core.reloc.RelocationFixupHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.util.CodeUnitInsertionException;

public class AmigaHunkRelocationFixupHandler extends RelocationFixupHandler {

	@Override
	public boolean processRelocation(Program program, Relocation relocation, Address oldImageBase, Address newImageBase)
			throws MemoryAccessException, CodeUnitInsertionException {
		return process32BitRelocation(program, relocation, oldImageBase, newImageBase);
	}

	@Override
	public boolean handlesProgram(Program program) {
		return AmigaHunkAnalyzer.isAmigaHunkLoader(program);
	}

}
