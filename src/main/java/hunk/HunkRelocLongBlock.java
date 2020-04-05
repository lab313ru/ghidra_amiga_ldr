package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

class HunkRelocLongBlock extends HunkRelocBlock {
	
	public HunkRelocLongBlock(HunkType type, BinaryReader reader, boolean isExecutable, int size) throws HunkParseError {
		super(type, reader, size);

		parse(reader, isExecutable);
		calcHunkSize(reader);
	}

	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		while (true) {
			try {
				int num = reader.readNextInt();
				
				if (num == 0) {
					break;
				}
				
				int hunkNum = reader.readNextInt();
				
				List<Reloc> toAdd = new ArrayList<>();
				
				for (int i = 0; i < num; ++i) {
					toAdd.add(new Reloc(reader.readNextInt(), size));
				}
				
				relocs.add(new RelocData(hunkNum, toAdd));
			} catch (IOException e) {
				throw new HunkParseError(e);
			}
		}
	}

}
