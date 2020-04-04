package hunk;

import java.util.List;

class RelocData {

	private final int hunkNum;
	private final List<Integer> offsets;
	
	RelocData(int hunkNum, final List<Integer> offsets) {
		this.hunkNum = hunkNum;
		this.offsets = offsets;
	}
	
	public final int getHunkNum() {
		return hunkNum;
	}
	
	public final int[] getOffsets() {
		int[] res = new int[offsets.size()];
		
		for (int i = 0; i < res.length; ++i) {
			res[i] = offsets.get(i);
		}
		
		return res;
	}
}
