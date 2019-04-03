package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkDebug {

	public static DebugInfo decode(BinaryReader reader) throws HunkParseError {
		long pos = reader.getPointerIndex();
		
		try {
			long dataSize = reader.length() - pos;
			
			if (dataSize < 12) {
				return null;
			}
		
			reader.readNextInt();
			String tag = reader.readNextAsciiString(4);

			switch (tag) {
				case "LINE":
					HunkBlock.readName(reader);
					return new HunkDebugLine();
				case "HEAD":
					String tag2 = reader.readNextAsciiString(4);

					if (!tag2.equals("DBGV01\u0000\u0000")) {
						throw new HunkParseError("Wrong debug tag (!= DBGV01\\x00\\x00)");
					}

					reader.readNextByteArray((int) (dataSize - reader.getPointerIndex()));
					return new HunkDebugAny();
				default:
					reader.readNextByteArray((int) (dataSize - reader.getPointerIndex()));
					return new HunkDebugAny();
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}
}
