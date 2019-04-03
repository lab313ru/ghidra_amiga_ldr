package hunk;

import ghidra.app.util.bin.BinaryReader;

class HunkBreakBlock extends HunkBlock {

	public HunkBreakBlock() {
		super(HunkType.HUNK_BREAK);
	}

	@Override
	public void parse(BinaryReader reader) {
		
	}

}
