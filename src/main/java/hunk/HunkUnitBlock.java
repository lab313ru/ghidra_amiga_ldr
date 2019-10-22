package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class HunkUnitBlock extends HunkBlock {
	
	private String name;
	
	HunkUnitBlock(BinaryReader reader) throws HunkParseError {
		super(HunkType.HUNK_UNIT, reader);
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
