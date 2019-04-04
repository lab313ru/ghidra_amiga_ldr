package hunk;

public enum SegmentType {
	SEGMENT_TYPE_CODE,
	SEGMENT_TYPE_DATA,
	SEGMENT_TYPE_BSS;

	SegmentType() {
	}

    @Override
	public String toString() {
		return name().substring("SEGMENT_TYPE_".length());
	}
}
