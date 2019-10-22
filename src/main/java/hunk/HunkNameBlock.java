package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkNameBlock extends HunkBlock {
	
	private String name;
	
	HunkNameBlock(BinaryReader reader) throws HunkParseError {
		super(HunkType.HUNK_NAME, reader);

		parse();
		calcHunkSize();
	}

	@Override
	void parse() throws HunkParseError {
		try {
			name = HunkBlock.readName(reader);
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

	public String getName() {
		return name;
	}
}
