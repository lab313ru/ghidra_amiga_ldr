package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

class HunkHeaderBlock extends HunkBlock {

	private final List<Integer> hunkTable;

	HunkHeaderBlock(BinaryReader reader) throws HunkParseError {
		super(HunkType.HUNK_HEADER, reader);
		
		hunkTable = new ArrayList<>();
		
		parse();
		calcHunkSize();
	}
	
	@Override
	void parse() throws HunkParseError {
		long startOffset = reader.getPointerIndex();
		
		while (true) {
			try {
				String name = HunkBlock.readName(reader);
				
				if (name == null) {
					throw new IOException();
				} else if (name.length() == 0) {
					break;
				}

			} catch (IOException e) {
				throw new HunkParseError("Error parsing HUNK_HEADER names");
			}
		}
		
		try {
			int tableSize = reader.readNextInt();
			int firstHunk = reader.readNextInt();
			int lastHunk = reader.readNextInt();
			
			if (tableSize < 0 || firstHunk < 0 || lastHunk < 0) {
				throw new HunkParseError("HUNK_HEADER invalid table_size or first_hunk or last_hunk");
			}
			
			for (int a = 0; a < lastHunk - firstHunk + 1; ++a) {
				int hunkSize = reader.readNextInt();
				
				if (hunkSize < 0) {
					throw new HunkParseError("HUNK_HEADER contains invalid hunk_size");
				}
				
				hunkTable.add(hunkSize & 0x3FFFFFFF);
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

	Integer[] getHunkTable() {
		return hunkTable.toArray(Integer[]::new);
	}
}
