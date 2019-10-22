package hunk;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

abstract class HunkRelocBlock extends HunkBlock {

	final List<RelocData> relocs;
	
	HunkRelocBlock(HunkType type, BinaryReader reader) {
		super(type, reader);

		this.relocs = new ArrayList<>();
	}
	
	public RelocData[] getRelocs() {
		return relocs.toArray(RelocData[]::new);
	}
}
