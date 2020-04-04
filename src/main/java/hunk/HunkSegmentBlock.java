package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkSegmentBlock extends HunkBlock {
	
	private byte[] data = null;
	private int sizeLongs = 0;
	
	HunkSegmentBlock(HunkType type, BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(type, reader);

		parse(reader, isExecutable);
		calcHunkSize(reader);
	}
	
	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		try {
			int size = sizeLongs = reader.readNextInt();
			
			if (super.getHunkType() != HunkType.HUNK_BSS) {
				size *= 4;
				data = reader.readNextByteArray(size);
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

    void setSizeLongs(int sizeLongs) {
		this.sizeLongs = sizeLongs;
	}
	
	byte[] getData() {
		return this.data;
	}

    int getSizeLongs() {
		return this.sizeLongs;
	}
}
