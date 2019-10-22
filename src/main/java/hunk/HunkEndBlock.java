package hunk;

import ghidra.app.util.bin.BinaryReader;

class HunkEndBlock extends HunkBlock {

	public HunkEndBlock(BinaryReader reader) throws HunkParseError {
		super(HunkType.HUNK_END, reader);
		parse();
		calcHunkSize();
	}

	@Override
	void parse() throws HunkParseError {
		// TODO Auto-generated method stub
	}
}
