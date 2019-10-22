package hunk;

import java.io.IOException;

import com.google.common.primitives.Bytes;

import ghidra.app.util.bin.BinaryReader;

public abstract class HunkBlock {
	private HunkType blkId;
	protected long hunkSize;
	protected BinaryReader reader;
	protected long startPos;
	
	HunkBlock(HunkType blkId, BinaryReader reader) {
		this.blkId = blkId;
		this.reader = reader;
		startPos = reader.getPointerIndex();
		hunkSize = 0;
	}
	
	static String readName(BinaryReader reader) throws IOException {
		int longsCount = reader.readNextInt();
		
		if (longsCount == 0) {
			return "";
		}
		
		return readNameSize(reader, longsCount);
	}
	
	protected static String readNameSize(BinaryReader reader, int longs) throws IOException {
		byte[] bytes = reader.readNextByteArray((longs & 0xFFFFFF) * 4);
		
		if (bytes.length < (longs & 0xFFFFFF) * 4) {
			return null;
		}
		
		int zeroIdx = Bytes.indexOf(bytes, (byte) 0);
		
		String name = new String(bytes);
		return (zeroIdx == -1) ? name : name.substring(0, zeroIdx);
	}
	
	public HunkType getHunkType() {
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
		case HUNK_DREL32:
		case HUNK_RELOC32SHORT:
		case HUNK_DEBUG:
		case HUNK_SYMBOL:
		case HUNK_NAME:
			return true;
		default:
			return false;
		}
	}
	
	static HunkBlock fromHunkType(Object type, BinaryReader reader) throws HunkParseError {

	    if (type == null) {
	        return null;
        }

		switch ((HunkType)type) {
		case HUNK_HEADER:
			return new HunkHeaderBlock(reader);
		case HUNK_CODE:
		case HUNK_DATA:
		case HUNK_BSS:
			return new HunkSegmentBlock((HunkType)type, reader);
		case HUNK_ABSRELOC32:
		case HUNK_RELRELOC16:
		case HUNK_RELRELOC8:
		case HUNK_DREL16:
		case HUNK_DREL8:
			return new HunkRelocLongBlock((HunkType)type, reader);
		case HUNK_RELOC32SHORT:
		case HUNK_DREL32:
			return new HunkRelocWordBlock((HunkType)type, reader);
		case HUNK_END:
			return new HunkEndBlock(reader);
		case HUNK_DEBUG:
			return new HunkDebugBlock(reader);
		case HUNK_SYMBOL:
			return new HunkSymbolBlock(reader);
		case HUNK_OVERLAY:
			return new HunkOverlayBlock(reader);
		case HUNK_BREAK:
			return new HunkBreakBlock(reader);
		case HUNK_UNIT:
			return new HunkUnitBlock(reader);
		case HUNK_NAME:
			return new HunkNameBlock(reader);
		case HUNK_EXT:
			return new HunkExtBlock(reader);
		case HUNK_LIB:
			return new HunkLibBlock(reader);
		case HUNK_INDEX:
			return new HunkIndexBlock(reader);
		default:
			return null;
		}
	}
	
	abstract void parse() throws HunkParseError;
	
	protected void calcHunkSize() {
		hunkSize += reader.getPointerIndex() - startPos;
	}
	
	public long getSize() {
		return hunkSize;
	}
}
