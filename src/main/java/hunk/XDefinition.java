package hunk;

public class XDefinition {
	private final boolean isGlobal;
	private final boolean isAbsolute;
	private final String name;
	private final int offset;
	
	public XDefinition(boolean isGlobal, boolean isAbsolute, String name, int offset) {
		this.isGlobal = isGlobal;
		this.isAbsolute = isAbsolute;
		this.name = name;
		this.offset = offset;
	}

	public boolean isGlobal() {
		return isGlobal;
	}

	public boolean isAbsolute() {
		return isAbsolute;
	}

	public String getName() {
		return name;
	}
	
	public int getOffset() {
		return offset;
	}
}
