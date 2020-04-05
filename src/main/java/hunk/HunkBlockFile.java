package hunk;

import java.io.IOException;
import java.util.SortedMap;
import java.util.TreeMap;

import ghidra.app.util.bin.BinaryReader;

public class HunkBlockFile {
	private SortedMap<Long, HunkBlock> blocksList;
	private HunkBlockType blockType;

	public static boolean isHunkBlockFile(BinaryReader reader) {
		return peekType(reader) != HunkBlockType.TYPE_UNKNOWN;
	}
	
	public HunkBlockFile(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		blocksList = new TreeMap<>();
		blockType = peekType(reader);
		parse(reader, isExecutable);
	}
	
	public SortedMap<Long, HunkBlock> getHunkBlocks() {
		return blocksList;
	}
	
	private void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		try {
			long pos = reader.getPointerIndex();
			while (pos + 4 <= reader.length()) {
				int tag = reader.readNextInt();

				HunkBlock block = HunkBlock.fromHunkType(HunkType.fromInteger(tag & HunkType.HUNK_TYPE_MASK), reader, isExecutable);
				
				if (block == null) {
					throw new HunkParseError(String.format("Unsupported hunk type: %04d", tag & HunkType.HUNK_TYPE_MASK));
				}

				blocksList.put(pos, block);
				
				pos = reader.getPointerIndex();
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}
	
	public HunkBlockType getHunkBlockType() {
		return blockType;
	}
	
	public static HunkBlockType peekType(BinaryReader reader) {
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
		if ((blkId == HunkType.HUNK_HEADER) || blkId == HunkType.HUNK_UNIT) {
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
