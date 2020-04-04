package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

class HunkExtBlock extends HunkBlock {
	
	private HashMap<String, Object> xdefsLocal; // Object can be Reloc or Integer
	private HashMap<String, Object> xdefsGlobal; // Object can be Reloc or Integer
	private HashMap<String, List<Object>> xrefs; // Object can be Reloc or Integer
	
	HunkExtBlock(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(HunkType.HUNK_EXT, reader);
		
		parse(reader, isExecutable);
		calcHunkSize(reader);
	}

	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		xdefsLocal = new HashMap<>();
		xdefsGlobal = new HashMap<>();
		xrefs = new HashMap<>();
		
		while (true) {
			try {
				long tag = reader.readNextUnsignedInt();

				if (tag == 0) {
					break;
				}

				ExtType extType = ExtType.fromInteger((int)(tag >> 24));

				String xname = readNameSize(reader, (int)(tag & 0xFFFFFF));

				switch (extType) {
				case EXT_SYMB: {
					xdefsLocal.put(xname, new Reloc(reader.readNextInt()));
				} break;
				case EXT_DEF: {
					xdefsGlobal.put(xname, new Reloc(reader.readNextInt()));
				} break;
				case EXT_ABS: {
					xdefsGlobal.put(xname, reader.readNextInt());
				} break;
				
				// Unresolved Symbol References
				case EXT_ABSREF32: 
				case EXT_ABSREF16: 
				case EXT_ABSREF8:
				case EXT_RELREF32: 
				case EXT_RELREF16: 
				case EXT_RELREF8: 
				case EXT_DEXT32: 
				case EXT_DEXT16:
				case EXT_DEXT8: {
					List<Object> relocs = Arrays.asList(readRelocs(reader, extType));
					xrefs.put(xname, relocs);
				} break;
				default: {
					throw new HunkParseError(String.format("Unsupported HUNK_EXT type: %s", extType.name()));
				}
				}
			} catch (IOException e) {
				throw new HunkParseError(e);
			}
		}
	}
	
	final HashMap<String, Object> getLocalDefs() {
		return xdefsLocal;
	}
	
	final HashMap<String, Object> getGlobalDefs() {
		return xdefsGlobal;
	}
	
	final HashMap<String, List<Object>> getXrefs() {
		return xrefs;
	}
	
	Object[] readRelocs(BinaryReader reader, ExtType extType) throws IOException {
		List<Object> relocs = new ArrayList<>();
		
		int numRefs = reader.readNextInt();
		
		if (numRefs == 0) {
			numRefs = 1;
		}
		
		for (int i = 0; i < numRefs; ++i) {
			int reloc = reader.readNextInt();
			
			switch (extType) {
			case EXT_ABSREF32: 
			case EXT_ABSREF16: 
			case EXT_ABSREF8: {
				relocs.add(reloc);
			} break;
			case EXT_RELREF32: 
			case EXT_RELREF16: 
			case EXT_RELREF8: 
			case EXT_DEXT32:
			case EXT_DEXT16:
			case EXT_DEXT8: {
				relocs.add(new Reloc(reloc));
			} break;
			default: continue;
			}
		}
		
		return relocs.toArray(Object[]::new);
	}

}
