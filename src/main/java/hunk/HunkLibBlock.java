package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkLibBlock extends HunkBlock {

	HunkLibBlock() {
		super(HunkType.HUNK_LIB);
	}

	@Override
	public void parse(BinaryReader reader) throws HunkParseError {
		try {
			int numLongs = reader.readNextInt();
			long pos = reader.getPointerIndex();
			long endPos = pos + numLongs * 4;
			
			while (pos < endPos && pos + 4 <= reader.length()) {
				int tag = reader.readNextInt();
				
				HunkBlock block = HunkBlock.fromHunkType(HunkType.fromInteger(tag & HunkType.HUNK_TYPE_MASK));
				
				if (block == null) {
					throw new HunkParseError(String.format("Unsupported hunk type: %04d", tag & HunkType.HUNK_TYPE_MASK));
				}
				
				block.parse(reader);
				
				pos = reader.getPointerIndex();
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

}
