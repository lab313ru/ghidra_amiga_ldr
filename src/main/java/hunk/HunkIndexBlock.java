package hunk;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class HunkIndexBlock extends HunkBlock {
	
	HunkIndexBlock() {
		super(HunkType.HUNK_INDEX);
	}

	@Override
	public void parse(BinaryReader reader) throws HunkParseError {
		try {
			int numWords = reader.readNextInt() * 2;
			
			int strtabSize = reader.readNextShort();
			reader.readNextByteArray(strtabSize);
			
			numWords = numWords - (strtabSize / 2) - 1;
			
			while (numWords > 1) {
				reader.readNextShort();
				reader.readNextShort();
				short numHunks = (short) (reader.readNextShort() - 3);
				
				for (int i = 0; i < numHunks; ++i) {
					reader.readNextShort();
					reader.readNextShort();
					reader.readNextShort();
					
					short numRefs = reader.readNextShort();
					
					for (int j = 0; j < numRefs; ++j) {
						reader.readNextShort();
					}
					
					short numDefs = reader.readNextShort();
					
					for (int j = 0; j < numDefs; ++j) {
						reader.readNextShort();
						reader.readNextShort();
						reader.readNextShort();
					}
					
					numWords = numWords - (5 + numRefs + numDefs * 3);
				}
			}
			
			if (numWords == 1) {
				reader.readNextShort();
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

}
