package hunk;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

abstract class HunkRelocBlock extends HunkBlock {

	final List<RelocData> relocs;
	final int size;
	
	HunkRelocBlock(HunkType type, BinaryReader reader, int size) {
		super(type, reader);

		this.relocs = new ArrayList<>();
		this.size = size; 
	}
	
	protected RelocData[] getRelocs() {
		return relocs.toArray(RelocData[]::new);
	}
}
