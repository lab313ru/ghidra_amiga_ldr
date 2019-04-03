package hunk;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;

public final class BinFmtHunk {
	
	public static boolean isImageFile(BinaryReader reader) {
		HunkBlockFile hbf = new HunkBlockFile();
		
		return hbf.peekType(reader) == HunkBlockType.TYPE_LOADSEG;
	}
	
	public static BinImage loadImage(BinaryReader reader, MessageLog log) {
		HunkBlockFile hbf = new HunkBlockFile();
		
		try {
			hbf.read(reader);
			
			HunkLoadSegFile lsf = new HunkLoadSegFile();
			lsf.parseBlockFile(hbf);
			
			return createImageFromLoadSegFile(lsf);
		} catch (HunkParseError e) {
			log.appendException(e);
		}
		
		return null;
	}
	
	private static BinImage createImageFromLoadSegFile(HunkLoadSegFile lsf) throws HunkParseError {
		BinImage bi = new BinImage();
		
		HunkSegment[] segs = lsf.getSegments();
		
		for (HunkSegment seg : segs) {
			int size = seg.getSizeLongs() * 4;
			HunkSegmentBlock segBlock = seg.getSegmentBlock();
			
			if (segBlock == null) {
				continue;
			}

			byte[] data = segBlock.getData();
			
			SegmentType segType;
			if (seg.getHunkType() == HunkType.HUNK_CODE) {
				segType = SegmentType.SEGMENT_TYPE_CODE;
			} else if (seg.getHunkType() == HunkType.HUNK_DATA) {
				segType = SegmentType.SEGMENT_TYPE_DATA;
			} else if (seg.getHunkType() == HunkType.HUNK_BSS ) {
				segType = SegmentType.SEGMENT_TYPE_BSS;
			} else {
				throw new HunkParseError(String.format("Unknown Segment Type for BinImage: %d", seg.getHunkType().getValue()));
			}
			
			Segment bs = new Segment(segType, size, data);
			bs.setFileData(seg);
			bi.addSegment(bs);
		}
		
		Segment[] biSegs = bi.getSegments();
		
		for (Segment seg : biSegs) {
			HunkSegment hSeg = seg.getFileData();
			HunkRelocBlock[] relocBlocks = hSeg.getRelocBlocks();
			
			if (relocBlocks != null) {
				addHunkRelocs(relocBlocks, seg, biSegs);
			}
		}
		
		return bi;
	}
	
	private static void addHunkRelocs(HunkRelocBlock[] relocBlocks, Segment seg, Segment[] allSegs) throws HunkParseError {
		for (HunkRelocBlock blk : relocBlocks) {
			if (blk.getHunkType() != HunkType.HUNK_ABSRELOC32 && blk.getHunkType() != HunkType.HUNK_RELOC32SHORT) {
				throw new HunkParseError(String.format("Invalid Relocations for BinImage: %d", blk.getHunkType().getValue()));
			}
			
			for (RelocData r : blk.getRelocs()) {
				int hunkNum = r.getHunkNum();
				int[] offsets = r.getOffsets();
				
				if (hunkNum < allSegs.length) {
					Segment toSeg = allSegs[hunkNum];
					
					Relocations rl = seg.getRelocations(toSeg);
					
					if (rl == null) {
						rl = new Relocations();
					}
					
					for (int o : offsets) {
						rl.addRelocation(new Reloc(o));
					}
					
					seg.addRelocation(toSeg, rl);
				} else {
					throw new HunkParseError("Invalid hunk segment number");
				}
			}
		}
	}
}
