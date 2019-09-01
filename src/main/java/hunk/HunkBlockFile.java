package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

class HunkBlockFile {
	private List<HunkBlock> blocksList;
	
	HunkBlockFile() {
		blocksList = new ArrayList<>();
	}
	
	HunkBlock[] getBlocks() {
		return blocksList.toArray(HunkBlock[]::new);
	}
	
	void read(BinaryReader reader) throws HunkParseError {
		try {
			while (reader.getPointerIndex() + 4 <= reader.length()) {
				int tag = reader.readNextInt();

				HunkBlock block = HunkBlock.fromHunkType(HunkType.fromInteger(tag & HunkType.HUNK_TYPE_MASK));
				
				if (block == null) {
					throw new HunkParseError(String.format("Unsupported hunk type: %04d", tag & HunkType.HUNK_TYPE_MASK));
				}
				
				block.parse(reader);
				blocksList.add(block);
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}
	
	HunkBlockType peekType(BinaryReader reader) {
		long pos = reader.getPointerIndex();
		
		try {
			int tag = reader.readNextInt();
			reader.setPointerIndex(pos);
			
			HunkType blkId = HunkType.fromInteger(tag);
			return mapHunkTypeToHunkBlockType(blkId);
		} catch (IOException e) {
			reader.setPointerIndex(pos);
			return HunkBlockType.TYPE_UNKNOWN;
		}
	}
	
	private static HunkBlockType mapHunkTypeToHunkBlockType(HunkType blkId) {
		if (blkId == HunkType.HUNK_HEADER) {
			return HunkBlockType.TYPE_LOADSEG;
		} else if (blkId == HunkType.HUNK_UNIT) {
			return HunkBlockType.TYPE_UNIT;
		} else if (blkId == HunkType.HUNK_LIB) {
			return HunkBlockType.TYPE_LIB;
		} else {
			return HunkBlockType.TYPE_UNKNOWN;
		}
	}
}
