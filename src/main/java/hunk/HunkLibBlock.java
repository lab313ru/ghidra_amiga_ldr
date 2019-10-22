package hunk;

import java.io.IOException;
import java.util.SortedMap;
import java.util.TreeMap;

import ghidra.app.util.bin.BinaryReader;

public class HunkLibBlock extends HunkBlock {
	
	private SortedMap<Long, HunkBlock> blocks;

	public HunkLibBlock(BinaryReader reader) throws HunkParseError {
		super(HunkType.HUNK_LIB, reader);

		blocks = new TreeMap<>();
		
		parse();
		calcHunkSize();
	}

	@Override
	void parse() throws HunkParseError {
		try {
			int numLongs = reader.readNextInt();
			long pos = reader.getPointerIndex();
			long endPos = pos + numLongs * 4;
			
			while (pos < endPos && pos + 4 <= reader.length()) {
				int tag = reader.readNextInt();
				
				HunkBlock block = HunkBlock.fromHunkType(HunkType.fromInteger(tag & HunkType.HUNK_TYPE_MASK), reader);
				
				if (block == null) {
					throw new HunkParseError(String.format("Unsupported hunk type: %04d", tag & HunkType.HUNK_TYPE_MASK));
				}
				
				blocks.put(pos, block);
				
				pos = reader.getPointerIndex();
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

	public SortedMap<Long, HunkBlock> getHunkBlocks() {
		return blocks;
	}
}
