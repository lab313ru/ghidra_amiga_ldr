package hunk;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import ghidra.app.util.importer.MessageLog;

public final class BinFmtHunk {

	public static BinImage loadImage(HunkBlockFile hbf, MessageLog log) {
		try {
			HunkLoadSegFile lsf = new HunkLoadSegFile();
			lsf.parseBlockFile(hbf);
			return createImageFromLoadSegFile(lsf);
		} catch (HunkParseError e) {
			log.appendException(e);
			return null;
		}
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
			bs.setSegmentInfo(seg);
			bi.addSegment(bs);
		}
		
		Segment[] biSegs = bi.getSegments();
		
		for (Segment seg : biSegs) {
			HunkSegment hSeg = seg.getSegmentInfo();
			HunkRelocBlock[] relocBlocks = hSeg.getRelocBlocks();
			
			if (relocBlocks != null) {
				addHunkRelocs(relocBlocks, seg, biSegs);
			}
		}
		
		return bi;
	}
	
	private static void addHunkRelocs(HunkRelocBlock[] relocBlocks, Segment seg, Segment[] allSegs) throws HunkParseError {
		for (HunkRelocBlock blk : relocBlocks) {
			for (RelocData r : blk.getRelocs()) {
				int hunkNum = r.getHunkNum();
				Reloc[] offsets = r.getRelocs();
				
				if (hunkNum >= allSegs.length) {
					throw new HunkParseError("Invalid hunk segment number");
				}
				
				Segment toSeg = allSegs[hunkNum];
				
				List<Reloc> rl = new ArrayList<>();
				rl.addAll(Arrays.asList(seg.getRelocations(toSeg)));
				rl.addAll(Arrays.asList(offsets));
				
				seg.addRelocations(toSeg, rl);
			}
		}
	}
}
