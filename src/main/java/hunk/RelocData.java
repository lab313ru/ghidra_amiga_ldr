package hunk;

import java.util.List;

class RelocData {

	private final int hunkNum;
	private final List<Reloc> relocs;
	
	RelocData(int hunkNum, final List<Reloc> relocs) {
		this.hunkNum = hunkNum;
		this.relocs = relocs;
	}
	
	public final int getHunkNum() {
		return hunkNum;
	}
	
	public final Reloc[] getRelocs() {
		return relocs.toArray(Reloc[]::new);
	}
}
