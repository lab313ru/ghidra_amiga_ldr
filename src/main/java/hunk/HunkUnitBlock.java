package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkUnitBlock extends HunkBlock {
	
	HunkUnitBlock() {
		super(HunkType.HUNK_UNIT);
	}

	@Override
	public void parse(BinaryReader reader) throws HunkParseError {
		try {
			HunkBlock.readName(reader);
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

}
