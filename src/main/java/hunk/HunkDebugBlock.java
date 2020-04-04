package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkDebugBlock extends HunkBlock {

	private byte[] debugData = null;
	
	public HunkDebugBlock(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(HunkType.HUNK_DEBUG, reader);
		
		parse(reader, isExecutable);
		calcHunkSize(reader);
	}

	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
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
