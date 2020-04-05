package hunk;

import java.util.List;

public class XReference {
	private final String name;
	private final List<Integer> offsets;
	private final XReferenceType type;
	private final int width;
	
	public XReference(String name, XReferenceType type, final List<Integer> offsets, int width) {
		this.name = name;
		this.type = type;
		this.offsets = offsets;
		this.width = width;
	}
	
	public String getName() {
		return name;
	}

	public final List<Integer> getOffsets() {
		return offsets;
	}

	public XReferenceType getType() {
		return type;
	}
	
	public int getWidth() {
		return width;
	}
}
