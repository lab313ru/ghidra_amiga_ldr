package hunk;

public class HunkIndexSymbolRef {
	private final String name;
	private final int width;

	public HunkIndexSymbolRef(String name, int width) {
		this.name = name;
		this.width = width;
	}

	public String getName() {
		return name;
	}
	
	public int getWidth() {
		return width;
	}
}
