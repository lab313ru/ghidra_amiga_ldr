package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

class HunkExtBlock extends HunkBlock {
	
	private List<XDefinition> xdefs;
	private List<XReference> xrefs;
	
	HunkExtBlock(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(HunkType.HUNK_EXT, reader);
		
		parse(reader, isExecutable);
		calcHunkSize(reader);
	}

	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		xdefs = new ArrayList<>();
		xrefs = new ArrayList<>();
		
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
					xdefs.add(new XDefinition(false, false, xname, reader.readNextInt()));
				} break;
				case EXT_DEF: {
					xdefs.add(new XDefinition(true, false, xname, reader.readNextInt()));
				} break;
				case EXT_ABS: {
					xdefs.add(new XDefinition(true, true, xname, reader.readNextInt()));
				} break;
				
				// Unresolved Symbol References
				case EXT_ABSREF32: {
					final List<Integer> relocs = Arrays.asList(readRelocs(reader, extType));
					xrefs.add(new XReference(xname, XReferenceType.R_ABS, relocs, 4));
				} break;
				case EXT_ABSREF16: {
					final List<Integer> relocs = Arrays.asList(readRelocs(reader, extType));
					xrefs.add(new XReference(xname, XReferenceType.R_ABS, relocs, 2));
				} break;
				case EXT_ABSREF8: {
					final List<Integer> relocs = Arrays.asList(readRelocs(reader, extType));
					xrefs.add(new XReference(xname, XReferenceType.R_ABS, relocs, 1));
				} break;
				case EXT_RELREF32: {
					final List<Integer> relocs = Arrays.asList(readRelocs(reader, extType));
					xrefs.add(new XReference(xname, XReferenceType.R_PC, relocs, 4));
				} break;
				case EXT_RELREF16: {
					final List<Integer> relocs = Arrays.asList(readRelocs(reader, extType));
					xrefs.add(new XReference(xname, XReferenceType.R_PC, relocs, 2));
				} break;
				case EXT_RELREF8: {
					final List<Integer> relocs = Arrays.asList(readRelocs(reader, extType));
					xrefs.add(new XReference(xname, XReferenceType.R_PC, relocs, 1));
				} break;
				case EXT_DEXT32: {
					final List<Integer> relocs = Arrays.asList(readRelocs(reader, extType));
					xrefs.add(new XReference(xname, XReferenceType.R_SD, relocs, 4));
				} break;
				case EXT_DEXT16: {
					final List<Integer> relocs = Arrays.asList(readRelocs(reader, extType));
					xrefs.add(new XReference(xname, XReferenceType.R_SD, relocs, 2));
				} break;
				case EXT_DEXT8: {
					final List<Integer> relocs = Arrays.asList(readRelocs(reader, extType));
					xrefs.add(new XReference(xname, XReferenceType.R_SD, relocs, 1));
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
	
	final List<XDefinition> getDefinitions() {
		return xdefs;
	}
	
	final List<XReference> getReferences() {
		return xrefs;
	}
	
	final Integer[] readRelocs(BinaryReader reader, ExtType extType) throws IOException {
		List<Integer> relocs = new ArrayList<>();
		
		int numRefs = reader.readNextInt();
		
		if (numRefs == 0) {
			numRefs = 1;
		}
		
		for (int i = 0; i < numRefs; ++i) {
			int reloc = reader.readNextInt();
			relocs.add(reloc);
		}
		
		return relocs.toArray(Integer[]::new);
	}

}
