package hunk;

import ghidra.app.util.bin.BinaryReader;

class HunkEndBlock extends HunkBlock {

	public HunkEndBlock(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(HunkType.HUNK_END, reader);
		
		parse(reader, isExecutable);
		calcHunkSize(reader);
	}

	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		// TODO Auto-generated method stub
	}
}
