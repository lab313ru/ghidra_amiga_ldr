package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkSymbolBlock extends HunkBlock {
	
	HunkSymbolBlock(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(HunkType.HUNK_SYMBOL, reader);
		
		parse(reader, isExecutable);
		calcHunkSize(reader);
	}

	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
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
