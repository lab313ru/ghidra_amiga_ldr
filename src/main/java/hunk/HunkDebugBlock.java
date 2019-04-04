package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkDebugBlock extends HunkBlock {

	private byte[] debugData = null;
	
	public HunkDebugBlock() {
		super(HunkType.HUNK_DEBUG);
	}

	@Override
	public void parse(BinaryReader reader) throws HunkParseError {
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
