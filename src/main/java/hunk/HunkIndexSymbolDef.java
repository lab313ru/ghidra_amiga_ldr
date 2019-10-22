package hunk;

public class HunkIndexSymbolDef {
	private final String name;
	private final short value;
	private final short symCtype;
	
	public HunkIndexSymbolDef(String name, short value, short symCtype) {
		this.name = name;
		this.value = value;
		this.symCtype = symCtype;
	}

	public String getName() {
		return name;
	}

	public short getValue() {
		return value;
	}

	public short getSymCtype() {
		return symCtype;
	}
}
