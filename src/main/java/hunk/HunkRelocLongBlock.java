package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

class HunkRelocLongBlock extends HunkRelocBlock {
	
	public HunkRelocLongBlock(HunkType type, BinaryReader reader) throws HunkParseError {
		super(type, reader);

		parse();
		calcHunkSize();
	}

	@Override
	void parse() throws HunkParseError {
		while (true) {
			try {
				int num = reader.readNextInt();
				
				if (num == 0) {
					break;
				}
				
				int hunkNum = reader.readNextInt();
				
				List<Integer> offsets = new ArrayList<>();
				
				for (int i = 0; i < num; ++i) {
					offsets.add(reader.readNextInt());
				}
				
				relocs.add(new RelocData(hunkNum, offsets));
			} catch (IOException e) {
				throw new HunkParseError(e);
			}
		}
	}

}
