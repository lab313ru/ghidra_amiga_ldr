package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

class HunkRelocWordBlock extends HunkRelocBlock {

	HunkRelocWordBlock(HunkType type, BinaryReader reader, boolean isExecutable, int size) throws HunkParseError {
		super(type, reader, size);

		parse(reader, isExecutable);
		calcHunkSize(reader);
	}
	
	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {		
		try {
			int numWords = 0;
			
			while (true) {
				int numOffs = reader.readNextUnsignedShort();
				numWords++;
				
				if (numOffs == 0) {
					break;
				}
				
				int hunkNum = reader.readNextUnsignedShort();
				numWords += numOffs + 1;
				
				List<Reloc> toAdd = new ArrayList<>();
				
				for (int i = 0; i < numOffs; ++i) {
					toAdd.add(new Reloc(reader.readNextUnsignedShort(), size));
				}
				
				relocs.add(new RelocData(hunkNum, toAdd));
			}
			
			if ((numWords % 2) == 1) {
				reader.readNextUnsignedShort();
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

}
