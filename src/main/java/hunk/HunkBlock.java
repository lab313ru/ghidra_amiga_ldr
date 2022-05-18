package hunk;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;

public abstract class HunkBlock {
	private HunkType blkId;
	protected int hunkSize;
	protected int startPos;
	
	HunkBlock(HunkType blkId, BinaryReader reader) {
		this.blkId = blkId;
		startPos = (int)reader.getPointerIndex();
		hunkSize = 4;
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
		
		return getStringFromOffset(bytes, 0);
	}
	
	protected static String getStringFromOffset(byte[] array, int offset) {
		if (offset < 0) {
			return null;
		}
		
		int indexEnd = offset;
		while (indexEnd < array.length && array[indexEnd] != 0) {
			++indexEnd;
		}
		int length = indexEnd - offset;
		if (length > 0) {
			try {
				return StandardCharsets.ISO_8859_1.newDecoder()
						.onMalformedInput(CodingErrorAction.REPLACE)
						.onUnmappableCharacter(CodingErrorAction.REPLACE)
						.replaceWith("?")
						.decode(ByteBuffer.wrap(array, offset, length)).toString();
			} catch (CharacterCodingException e) {
				// this should never happen due to CodingErrorAction.REPLACE
				return "?".repeat(length);
			}
		}
		return new String();
	}
	
	public HunkType getHunkType() {
		return blkId;
	}
	
	boolean isValidLoadsegBeginHunk() {
		switch (blkId) {
		case HUNK_CODE:
		case HUNK_DATA:
		case HUNK_BSS:
		// case HUNK_PPC_CODE:
			return true;
		default:
			return false;
		}
	}
	
	boolean isValidLoadsegExtraHunk() {
		switch (blkId) {
		case HUNK_ABSRELOC32:
		case HUNK_ABSRELOC16:
		case HUNK_RELRELOC32:
		case HUNK_RELRELOC26:
		case HUNK_RELRELOC16:
		case HUNK_RELRELOC8:
		case HUNK_DREL32:
		case HUNK_DREL16:
		case HUNK_DREL8:
		case HUNK_RELOC32SHORT:
		case HUNK_DEBUG:
		case HUNK_SYMBOL:
		case HUNK_NAME:
		case HUNK_EXT:
			return true;
		default:
			return false;
		}
	}
	
	static HunkBlock fromHunkType(Object type, BinaryReader reader, boolean isExecutable) throws HunkParseError {

	    if (type == null) {
	        return null;
        }

		switch ((HunkType)type) {
		case HUNK_HEADER:
			return new HunkHeaderBlock(reader, isExecutable);
		case HUNK_CODE:
		case HUNK_DATA:
		case HUNK_BSS:
			return new HunkSegmentBlock((HunkType)type, reader, isExecutable);
		case HUNK_ABSRELOC32:
			return new HunkRelocLongBlock((HunkType)type, reader, isExecutable, 4);
		case HUNK_RELRELOC16:
			return new HunkRelocLongBlock((HunkType)type, reader, isExecutable, 2);
		case HUNK_RELRELOC8:
			return new HunkRelocLongBlock((HunkType)type, reader, isExecutable, 1);
		case HUNK_DREL32:
			if (isExecutable) {
				return new HunkRelocWordBlock((HunkType)type, reader, isExecutable, 4);
			} else {
				return new HunkRelocLongBlock((HunkType)type, reader, isExecutable, 4);
			}
		case HUNK_DREL16:
			return new HunkRelocLongBlock((HunkType)type, reader, isExecutable, 2);
		case HUNK_DREL8:
			return new HunkRelocLongBlock((HunkType)type, reader, isExecutable, 1);
		case HUNK_RELOC32SHORT:
			return new HunkRelocWordBlock((HunkType)type, reader, isExecutable, 4);
		case HUNK_END:
			return new HunkEndBlock(reader, isExecutable);
		case HUNK_DEBUG:
			return new HunkDebugBlock(reader, isExecutable);
		case HUNK_SYMBOL:
			return new HunkSymbolBlock(reader, isExecutable);
		case HUNK_OVERLAY:
			return new HunkOverlayBlock(reader, isExecutable);
		case HUNK_BREAK:
			return new HunkBreakBlock(reader, isExecutable);
		case HUNK_UNIT:
			return new HunkUnitBlock(reader, isExecutable);
		case HUNK_NAME:
			return new HunkNameBlock(reader, isExecutable);
		case HUNK_EXT:
			return new HunkExtBlock(reader, isExecutable);
		case HUNK_LIB:
			return new HunkLibBlock(reader, isExecutable);
		case HUNK_INDEX:
			return new HunkIndexBlock(reader, isExecutable);
		default:
			return null;
		}
	}
	
	abstract void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError;
	
	protected void calcHunkSize(BinaryReader reader) {
		hunkSize += reader.getPointerIndex() - startPos;
	}
	
	public int getSize() {
		return hunkSize;
	}
}
