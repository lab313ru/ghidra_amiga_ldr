package hunk;

import java.util.ArrayList;
import java.util.List;

public class HunkIndexUnitEntry {
	private final int firstHunkLongOff;
	private final String name;
	
	private List<HunkIndexHunkEntry> indexHunks;
	
	public HunkIndexUnitEntry(String name, int firstHunkLongOff) {
		this.name = name;
		this.firstHunkLongOff = firstHunkLongOff;
		indexHunks = new ArrayList<>();
	}

	public String getName() {
		return name;
	}

	public int getFirstHunkLongOff() {
		return firstHunkLongOff;
	}
	
	public void addIndexHunk(HunkIndexHunkEntry indexHunk) {
		indexHunks.add(indexHunk);
	}
	
	public HunkIndexHunkEntry[] getHunkIndexHunkEntries() {
		return indexHunks.toArray(HunkIndexHunkEntry[]::new);
	}
}
