package hunk;

import java.util.ArrayList;
import java.util.List;

public class Relocations {
	
	private final List<Reloc> entries;
	
	Relocations() {
		entries = new ArrayList<>();
	}
	
	void addRelocation(Reloc reloc) {
		entries.add(reloc);
	}
	
	public Reloc[] getRelocations() {
		return entries.toArray(Reloc[]::new);
	}
}
