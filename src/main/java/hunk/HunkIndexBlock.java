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
	
	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		try {
			int numWords = reader.readNextInt() * 2;
			
			int strtabSize = reader.readNextUnsignedShort();
			strtab = reader.readNextByteArray(strtabSize);
			
			numWords = numWords - (strtabSize / 2) - 1;
			
			while (numWords > 1) {
				int nameOff = reader.readNextUnsignedShort();
				int firstHunkLongOff = reader.readNextUnsignedShort();
				int numHunks = reader.readNextUnsignedShort();
				numWords -= 3;
				
				String name = getStringFromOffset(strtab, nameOff);
				
				HunkIndexUnitEntry unitEntry = new HunkIndexUnitEntry(name, firstHunkLongOff);
				units.add(unitEntry);
				
				for (int i = 0; i < numHunks; ++i) {
					nameOff = reader.readNextUnsignedShort();
					int hunkLongs = reader.readNextUnsignedShort();
					int hunkCtype = reader.readNextUnsignedShort();
					
					name = getStringFromOffset(strtab, nameOff);

					HunkIndexHunkEntry hunkEntry = new HunkIndexHunkEntry(name, hunkLongs, hunkCtype);
					unitEntry.addIndexHunk(hunkEntry);
					
					int numRefs = reader.readNextUnsignedShort();
					
					for (int j = 0; j < numRefs; ++j) {
						nameOff = reader.readNextUnsignedShort();
						name = getStringFromOffset(strtab, nameOff);
						int width = 4;
						
						if (name.isEmpty()) {
							name = getStringFromOffset(strtab, nameOff + 1);
							width = 2;
						}
						
						hunkEntry.addSymRef(new HunkIndexSymbolRef(name, width));
					}
					
					int numDefs = reader.readNextUnsignedShort();
					
					for (int j = 0; j < numDefs; ++j) {
						nameOff = reader.readNextUnsignedShort();
						int value = reader.readNextUnsignedShort();
						int stype = reader.readNextUnsignedShort();
						
						name = getStringFromOffset(strtab, nameOff);
						
						hunkEntry.addSymDef(new HunkIndexSymbolDef(name, value, stype));
					}
					
					numWords = numWords - (5 + numRefs + numDefs * 3);
				}
			}
			
			if (numWords == 1) {
				reader.readNextUnsignedShort();
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
