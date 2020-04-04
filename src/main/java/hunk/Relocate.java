package hunk;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class Relocate {

	private final BinImage binImage;
	
	public Relocate(BinImage binImage) {
		if (binImage == null) {
			this.binImage = new BinImage();
		} else {
			this.binImage = binImage;
		}
	}
	
	private int[] getSizes() {
		Segment[] segs = binImage.getSegments();
		int[] sizes = new int[segs.length];
		
		for (int i = 0; i < segs.length; ++i) {
			sizes[i] = segs[i].getSize();
		}
		
		return sizes;
	}
	
	public long[] getSeqAddresses(long baseAddr) {
		int[] sizes = getSizes();
		long[] addrs = new long[sizes.length];
		
		long addr = baseAddr;
		for (int i = 0; i < sizes.length; ++i) {
			addrs[i] = addr;
			addr += sizes[i];
		}
		
		return addrs;
	}
	
	public List<byte[]> relocate(long[] addrs) throws HunkParseError {
		Segment[] segs = binImage.getSegments();
		
		if (segs.length != addrs.length) {
			throw new HunkParseError("Reloc addrs != Reloc segments");
		}
		
		List<byte[]> datas = new ArrayList<>();
		
		for (Segment seg : segs) {
			byte[] data = new byte[seg.getSize()];
			copyData(data, seg);
			relocData(data, seg, addrs);
			datas.add(data);
		}
		
		return datas;
	}

	private static void copyData(byte[] data, Segment seg) {
		byte[] srcData = seg.getData();
		
		if (srcData != null) {
			int srcLen = srcData.length;
			
			System.arraycopy(srcData, 0, data, 0, srcLen);
		}
	}

	private static void relocData(byte[] data, Segment seg, long[] addrs) {
		Segment[] toSegs = seg.getRelocationsToSegments();
		
		for (Segment toSeg : toSegs) {
			Reloc[] relocs = seg.getRelocations(toSeg);
			
			for (Reloc r : relocs) {
				reloc(data, r, addrs[toSeg.getId()]);
			}
		}
	}
	
	private static void reloc(byte[] data, Reloc reloc, long toAddr) {
		int offset = reloc.getOffset();
		
		ByteBuffer buf = ByteBuffer.wrap(data);
		int delta = buf.getInt(offset) + reloc.getAddend();
		buf.putInt(offset, (int)(toAddr + delta));
	}
}
