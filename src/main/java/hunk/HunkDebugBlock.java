package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkDebugBlock extends HunkBlock {

	private byte[] debugData = null;
	
	public HunkDebugBlock(BinaryReader reader) throws HunkParseError {
		super(HunkType.HUNK_DEBUG, reader);
		parse();
		calcHunkSize();
	}

	@Override
	void parse() throws HunkParseError {
		try {
			int numLongs = reader.readNextInt();
			debugData = reader.readNextByteArray(numLongs * 4);
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}
	
	public byte[] getData() {
		return debugData;
	}
}
