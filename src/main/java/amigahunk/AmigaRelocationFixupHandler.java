package amigahunk;

import ghidra.app.plugin.core.reloc.RelocationFixupHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.util.CodeUnitInsertionException;

public class AmigaRelocationFixupHandler extends RelocationFixupHandler { // NO_UCD (unused code)

	@Override
	public boolean processRelocation(Program program, Relocation relocation, Address oldImageBase, Address newImageBase)
			throws MemoryAccessException, CodeUnitInsertionException {
		return process32BitRelocation(program, relocation, oldImageBase, newImageBase);
	}

	@Override
	public boolean handlesProgram(Program program) {
		if (!program.getExecutableFormat().equals(AmigaHunkLoader.AMIGA_HUNK)) {
			return false;
		}
		
		Language language = program.getLanguage();
		if (language.getLanguageDescription().getSize() != 32) {
			return false;
		}
		Processor processor = language.getProcessor();
		return (processor.equals(Processor.findOrPossiblyCreateProcessor("68000"))); 
	}

}
