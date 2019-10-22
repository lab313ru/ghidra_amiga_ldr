package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkExtBlock extends HunkBlock {
	
	HunkExtBlock(BinaryReader reader) throws HunkParseError {
		super(HunkType.HUNK_EXT, reader);
		parse();
		calcHunkSize();
	}

	@Override
	void parse() throws HunkParseError {
		while (true) {
			try {
				long tag = reader.readNextUnsignedInt();

				if (tag == 0) {
					break;
				}

				ExtType extType = ExtType.fromInteger((int)(tag >> 24));

				readNameSize(reader, (int)(tag & 0xFFFFFF));

				if (extType == null) {
					throw new IOException();
				} else if (
						extType == ExtType.EXT_ABSCOMMON ||
						extType == ExtType.EXT_RELCOMMON ||
						extType == ExtType.EXT_DEF ||
						extType == ExtType.EXT_ABS ||
						extType == ExtType.EXT_RES
						) {
					reader.readNextInt();
				} else {
					int numRefs = reader.readNextInt();
					
					if (numRefs == 0) {
						numRefs = 1;
					}
					
					for (int i = 0; i < numRefs; ++i) {
						reader.readNextInt();
					}
				}
			} catch (IOException e) {
				throw new HunkParseError(e);
			}
		}
	}

}
