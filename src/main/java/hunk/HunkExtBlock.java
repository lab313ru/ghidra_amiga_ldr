package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkExtBlock extends HunkBlock {
	
	HunkExtBlock() {
		super(HunkType.HUNK_EXT);
	}

	@Override
	public void parse(BinaryReader reader) throws HunkParseError {
		while (true) {
			try {
				int tag = reader.readNextInt();

				if (tag == 0) {
					break;
				}

				ExtType extType = ExtType.fromInteger(tag >> 24);

				reader.readNextAsciiString(tag & 0xFFFFFF);

				if (extType == null) {
					throw new IOException();
				} else if (extType == ExtType.EXT_ABSCOMMON) {
					reader.readNextInt();
				} else if (extType.getIntValue() >= 0x80) {
					int numRefs = reader.readNextInt();
					
					for (int i = 0; i < numRefs; ++i) {
						reader.readNextUnsignedInt();
					}
				} else {
					reader.readNextInt();
				}
			} catch (IOException e) {
				throw new HunkParseError(e);
			}
		}
	}

}
