package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkSymbolBlock extends HunkBlock {
	
	HunkSymbolBlock() {
		super(HunkType.HUNK_SYMBOL);
	}

	@Override
	public void parse(BinaryReader reader) throws HunkParseError {
		try {
			while (true) {
				String name = HunkBlock.readName(reader);
				
				if (name == null || name.length() == 0) {
					break;
				}
				
				reader.readNextUnsignedInt();
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

}
