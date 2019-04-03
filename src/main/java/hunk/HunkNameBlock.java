package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkNameBlock extends HunkBlock {
	
	HunkNameBlock() {
		super(HunkType.HUNK_NAME);
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
