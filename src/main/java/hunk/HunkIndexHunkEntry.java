package hunk;

import java.util.ArrayList;
import java.util.List;

public class HunkIndexHunkEntry {
	private final String name;
	private final int hunkLongs;
	private final int hunkCtype;
	
	private List<HunkIndexSymbolRef> symRefs;
	private List<HunkIndexSymbolDef> symDefs;
	
	public HunkIndexHunkEntry(String name, int hunkLongs, int hunkCtype) {
		this.name = name;
		this.hunkLongs = hunkLongs;
		this.hunkCtype = hunkCtype;
		
		symRefs = new ArrayList<>();
		symDefs = new ArrayList<>();
	}
	
	public String getName() {
		return name;
	}

	public int getHunkLongs() {
		return hunkLongs;
	}

	public int getHunkCtype() {
		return hunkCtype;
	}

	public HunkIndexSymbolRef[] getSymRefs() {
		return symRefs.toArray(HunkIndexSymbolRef[]::new);
	}

	public HunkIndexSymbolDef[] getSymDefs() {
		return symDefs.toArray(HunkIndexSymbolDef[]::new);
	}
	
	public void addSymRef(HunkIndexSymbolRef symRef) {
		symRefs.add(symRef);
	}
	
	public void addSymDef(HunkIndexSymbolDef symDef) {
		symDefs.add(symDef);
	}
}
