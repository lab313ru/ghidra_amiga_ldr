package hunk;

import java.util.ArrayList;
import java.util.List;

public class HunkIndexUnitEntry {
	private final short firstHunkLongOff;
	private final String name;
	
	private List<HunkIndexHunkEntry> indexHunks;
	
	public HunkIndexUnitEntry(String name, short firstHunkLongOff) {
		this.name = name;
		this.firstHunkLongOff = firstHunkLongOff;
		indexHunks = new ArrayList<>();
	}

	public String getName() {
		return name;
	}

	public short getFirstHunkLongOff() {
		return firstHunkLongOff;
	}
	
	public void addIndexHunk(HunkIndexHunkEntry indexHunk) {
		indexHunks.add(indexHunk);
	}
	
	public HunkIndexHunkEntry[] getHunkIndexHunkEntries() {
		return indexHunks.toArray(HunkIndexHunkEntry[]::new);
	}
}
