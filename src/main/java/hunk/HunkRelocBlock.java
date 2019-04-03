package hunk;

import java.util.ArrayList;
import java.util.List;

abstract class HunkRelocBlock extends HunkBlock {

	final List<RelocData> relocs;
	
	HunkRelocBlock(HunkType type) {
		super(type);

		this.relocs = new ArrayList<>();
	}
	
	public RelocData[] getRelocs() {
		return relocs.toArray(RelocData[]::new);
	}
}
