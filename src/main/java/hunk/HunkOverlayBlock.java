package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkOverlayBlock extends HunkBlock {
	
	HunkOverlayBlock(BinaryReader reader) throws HunkParseError {
		super(HunkType.HUNK_OVERLAY, reader);

		parse();
		calcHunkSize();
	}

	@Override
	void parse() throws HunkParseError {
		try {
			int numLongs = reader.readNextInt();
			reader.getPointerIndex();
			reader.readNextByteArray(numLongs * 4);
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

}
