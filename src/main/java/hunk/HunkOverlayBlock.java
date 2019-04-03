package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkOverlayBlock extends HunkBlock {
	
	HunkOverlayBlock() {
		super(HunkType.HUNK_OVERLAY);
	}

	@Override
	public void parse(BinaryReader reader) throws HunkParseError {
		try {
			int numLongs = reader.readNextInt();
			reader.getPointerIndex();
			reader.readNextByteArray(numLongs * 4);
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

}
