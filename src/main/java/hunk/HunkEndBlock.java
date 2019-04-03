package hunk;

import ghidra.app.util.bin.BinaryReader;

class HunkEndBlock extends HunkBlock {

	public HunkEndBlock() {
		super(HunkType.HUNK_END);
	}

	@Override
	public void parse(BinaryReader reader) {
		
	}

}
