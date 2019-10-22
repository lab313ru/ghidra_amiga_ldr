package hunk;

import ghidra.app.util.bin.BinaryReader;

class HunkBreakBlock extends HunkBlock {

	public HunkBreakBlock(BinaryReader reader) throws HunkParseError {
		super(HunkType.HUNK_BREAK, reader);
		parse();
		calcHunkSize();
	}

	@Override
	void parse() throws HunkParseError {
		// TODO Auto-generated method stub
	}
}
