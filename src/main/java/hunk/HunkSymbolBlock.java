package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkSymbolBlock extends HunkBlock {
	
	HunkSymbolBlock(BinaryReader reader) throws HunkParseError {
		super(HunkType.HUNK_SYMBOL, reader);

		parse();
		calcHunkSize();
	}

	@Override
	void parse() throws HunkParseError {
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
