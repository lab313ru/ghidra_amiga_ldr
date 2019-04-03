package hunk;

import java.util.ArrayList;
import java.util.List;

public class BinImage {

	private final List<Segment> segments;

	BinImage() {
		segments = new ArrayList<>();
	}

	void addSegment(Segment seg) {
		seg.setId(segments.size());
		segments.add(seg);
	}

	public Segment[] getSegments() {
		return segments.toArray(Segment[]::new);
	}
}
