package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

class HunkRelocWordBlock extends HunkRelocBlock {

	HunkRelocWordBlock() {
		super(HunkType.HUNK_RELOC32SHORT);
	}
	
	@Override
	public void parse(BinaryReader reader) throws HunkParseError {		
		try {
			int numWords = 0;
			
			while (true) {
				int numOffs = reader.readNextShort();
				numWords++;
				
				if (numOffs == 0) {
					break;
				}
				
				int hunkNum = reader.readNextShort();
				numWords += numOffs + 1;
				
				List<Integer> offsets = new ArrayList<>();
				
				for (int i = 0; i < numOffs; ++i) {
					offsets.add((int) reader.readNextShort());
				}
				
				super.relocs.add(new RelocData(hunkNum, offsets));
			}
			
			if ((numWords % 2) == 1) {
				reader.readNextShort();
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

}
