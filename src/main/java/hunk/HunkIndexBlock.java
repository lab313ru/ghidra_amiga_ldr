package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

public class HunkIndexBlock extends HunkBlock {
	
	private List<HunkIndexUnitEntry> units;
	private byte[] strtab;

	HunkIndexBlock(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(HunkType.HUNK_INDEX, reader);
		
		units = new ArrayList<>();
		strtab = null;
		
		parse(reader, isExecutable);
		calcHunkSize(reader);
	}
	
	private static String getStringFromOffset(byte[] array, int offset) {
		int i;
		for (i = offset; i < array.length && array[i] != 0; i++) { }
		return new String(array, offset, i - offset);
	}

	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		try {
			int numWords = reader.readNextInt() * 2;
			
			int strtabSize = reader.readNextShort();
			strtab = reader.readNextByteArray(strtabSize);
			
			numWords = numWords - (strtabSize / 2) - 1;
			
			while (numWords > 1) {
				short nameOff = reader.readNextShort();
				short firstHunkLongOff = reader.readNextShort();
				short numHunks = (short) (reader.readNextShort() - 3);
				
				String name = getStringFromOffset(strtab, nameOff);
				
				HunkIndexUnitEntry unitEntry = new HunkIndexUnitEntry(name, firstHunkLongOff);
				units.add(unitEntry);
				
				for (int i = 0; i < numHunks; ++i) {
					nameOff = reader.readNextShort();
					short hunkLongs = reader.readNextShort();
					short hunkCtype = reader.readNextShort();
					
					name = getStringFromOffset(strtab, nameOff);
					
					HunkIndexHunkEntry hunkEntry = new HunkIndexHunkEntry(name, hunkLongs, hunkCtype);
					unitEntry.addIndexHunk(hunkEntry);
					
					short numRefs = reader.readNextShort();
					
					for (int j = 0; j < numRefs; ++j) {
						nameOff = reader.readNextShort();
						
						if (nameOff < strtab.length) {
							name = getStringFromOffset(strtab, nameOff);
						} else {
							name = "";
						}
						
						hunkEntry.addSymRef(new HunkIndexSymbolRef(name));
					}
					
					short numDefs = reader.readNextShort();
					
					for (int j = 0; j < numDefs; ++j) {
						nameOff = reader.readNextShort();
						short value = reader.readNextShort();
						short stype = reader.readNextShort();
						
						name = getStringFromOffset(strtab, nameOff);
						
						hunkEntry.addSymDef(new HunkIndexSymbolDef(name, value, stype));
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
	
	public HunkIndexUnitEntry[] getHunkIndexUnitEntries() {
		return units.toArray(HunkIndexUnitEntry[]::new);
	}

	public byte[] getStrtab() {
		return strtab;
	}

}
