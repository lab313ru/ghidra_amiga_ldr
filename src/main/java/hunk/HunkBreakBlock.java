package hunk;

import ghidra.app.util.bin.BinaryReader;

class HunkBreakBlock extends HunkBlock {

	public HunkBreakBlock(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(HunkType.HUNK_BREAK, reader);
		
		parse(reader, isExecutable);
		calcHunkSize(reader);
	}

	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		// TODO Auto-generated method stub
	}
}
