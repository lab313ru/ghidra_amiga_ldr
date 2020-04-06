package hunk;

public class HunkIndexSymbolDef {
	private final String name;
	private final int value;
	private final int symCtype;
	
	public HunkIndexSymbolDef(String name, int value, int symCtype) {
		this.name = name;
		this.value = value;
		this.symCtype = symCtype;
	}

	public String getName() {
		return name;
	}

	public int getValue() {
		return value;
	}

	public int getSymCtype() {
		return symCtype;
	}
}
