package hunk;

public class Symbol {

	private final int offset;
	private final String name;
	
	Symbol(int offset, String name) {
		this.offset = offset;
		this.name = name;
	}

	public final int getOffset() {
		return offset;
	}

	public final String getName() {
		return name;
	}
	
}
