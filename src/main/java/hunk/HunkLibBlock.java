package hunk;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import generic.stl.Pair;
import ghidra.app.util.bin.BinaryReader;

public class HunkLibBlock extends HunkBlock {
	
	private List<Pair<Integer, HunkBlock>> blocks;

	public HunkLibBlock(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		super(HunkType.HUNK_LIB, reader);
		
		parse(reader, isExecutable);
		calcHunkSize(reader);
	}

	@Override
	void parse(BinaryReader reader, boolean isExecutable) throws HunkParseError {
		blocks = new ArrayList<>();
		
		try {
			int numLongs = reader.readNextInt();
			long pos = reader.getPointerIndex();
			long endPos = pos + numLongs * 4;
			
			while (pos < endPos && pos + 4 <= reader.length()) {
				int tag = reader.readNextInt();
				
				HunkBlock block = HunkBlock.fromHunkType(HunkType.fromInteger(tag & HunkType.HUNK_TYPE_MASK), reader, isExecutable);
				
				if (block == null) {
					throw new HunkParseError(String.format("Unsupported hunk type: %04d", tag & HunkType.HUNK_TYPE_MASK));
				}
				
				blocks.add(new Pair<>((int)pos, block));
				
				pos = reader.getPointerIndex();
			}
		} catch (IOException e) {
			throw new HunkParseError(e);
		}
	}

	public final List<Pair<Integer, HunkBlock>> getHunkBlocks() {
		return blocks;
	}
}
