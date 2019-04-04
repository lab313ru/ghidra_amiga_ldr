package hunk;

import java.util.HashMap;
import java.util.HashSet;

public class Segment {

	private final SegmentType type;
	private final int segSize;
	private final byte[] data;
	private final HashMap<Segment, Relocations> relocsList;
	private int id;
	private HunkSegment fileData;
	
	Segment(SegmentType type, int size, byte[] data) {
		this.type = type;
		this.segSize = size;
		this.data = data;
		fileData = null;
		
		relocsList = new HashMap<>();
		
		id = -1;
	}
	
	public final SegmentType getType() {
		return type;
	}

	public final int getSize() {
		return segSize;
	}

    final byte[] getData() {
		return data;
	}

    void setFileData(HunkSegment seg) {
		fileData = seg;
	}
	
	HunkSegment getFileData() {
		return fileData;
	}
	
	public int getId() {
		return id;
	}
	
	public void setId(int id) {
		this.id = id;
	}
	
	void addRelocation(Segment segment, Relocations relocs) {
		this.relocsList.put(segment, relocs);
	}
	
	public Segment[] getRelocationsToSegments() {
		return new HashSet<>(relocsList.keySet()).toArray(Segment[]::new);
	}
	
	public Relocations getRelocations(Segment toSeg) {
		return relocsList.getOrDefault(toSeg, null);
	}

}
