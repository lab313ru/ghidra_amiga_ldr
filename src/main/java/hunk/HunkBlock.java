package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

abstract class HunkBlock implements IHunkBlock {
	private HunkType blkId;
	
	HunkBlock(HunkType blkId) {
		this.blkId = blkId;
	}
	
	static String readName(BinaryReader reader) throws IOException {
		int longsCount = reader.readNextInt();
		
		if (longsCount == 0) {
			return "";
		}
		
		return readNameSize(reader, longsCount);
	}
	
	private static String readNameSize(BinaryReader reader, int longs) throws IOException {
		byte[] bytes = reader.readNextByteArray((longs & 0xFFFFFF) * 4);
		
		if (bytes.length < (longs & 0xFFFFFF) * 4) {
			return null;
		}
		
		return new String(bytes);
	}
	
	void setReloc32ShortType() {
		blkId = HunkType.HUNK_RELOC32SHORT;
	}
	
	HunkType getHunkType() {
		return blkId;
	}
	
	boolean isValidLoadsegBeginHunk() {
		switch (blkId) {
		case HUNK_CODE:
		case HUNK_DATA:
		case HUNK_BSS:
		case HUNK_PPC_CODE:
			return true;
		default:
			return false;
		}
	}
	
	boolean isValidLoadsegExtraHunk() {
		switch (blkId) {
		case HUNK_ABSRELOC32:
		case HUNK_RELOC32SHORT:
		case HUNK_DEBUG:
		case HUNK_SYMBOL:
		case HUNK_NAME:
			return true;
		default:
			return false;
		}
	}
	
	static HunkBlock fromHunkType(Object type) {

	    if (type == null) {
	        return null;
        }

		switch ((HunkType)type) {
		case HUNK_HEADER:
			return new HunkHeaderBlock();
		case HUNK_CODE:
		case HUNK_DATA:
		case HUNK_BSS:
			return new HunkSegmentBlock((HunkType)type);
		case HUNK_ABSRELOC32:
		case HUNK_RELRELOC16:
		case HUNK_RELRELOC8:
		case HUNK_DREL32:
		case HUNK_DREL16:
		case HUNK_DREL8:
			return new HunkRelocLongBlock();
		case HUNK_RELOC32SHORT:
			return new HunkRelocWordBlock();
		case HUNK_END:
			return new HunkEndBlock();
		case HUNK_DEBUG:
			return new HunkDebugBlock();
		case HUNK_SYMBOL:
			return new HunkSymbolBlock();
		case HUNK_OVERLAY:
			return new HunkOverlayBlock();
		case HUNK_BREAK:
			return new HunkBreakBlock();
		case HUNK_UNIT:
			return new HunkUnitBlock();
		case HUNK_NAME:
			return new HunkNameBlock();
		case HUNK_EXT:
			return new HunkExtBlock();
		case HUNK_LIB:
			return new HunkLibBlock();
		case HUNK_INDEX:
			return new HunkIndexBlock();
		default:
			return null;
		}
	}
}
