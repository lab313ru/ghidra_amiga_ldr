package hunk;

import java.util.List;

class SymbolData {

	private final int hunkNum;
	private final List<Symbol> symbols;
	
	SymbolData(int hunkNum, final List<Symbol> symbols) {
		this.hunkNum = hunkNum;
		this.symbols = symbols;
	}
	
	public final int getHunkNum() {
		return hunkNum;
	}
	
	public final Symbol[] getSymbols() {
		return symbols.toArray(Symbol[]::new);
	}
}
