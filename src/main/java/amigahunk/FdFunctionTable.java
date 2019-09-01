package amigahunk;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class FdFunctionTable {

	private List<FdFunction> funcs;
	private final String lib;
	private HashMap<Integer, FdFunction> biasMap;
	private HashMap<String, FdFunction> nameMap;
	private List<FdFunction> indexTab;
	
	FdFunctionTable(String lib) {
		funcs = new ArrayList<FdFunction>();
		
		this.lib = lib;
		this.biasMap = new HashMap<Integer, FdFunction>();
		this.nameMap = new HashMap<String, FdFunction>();
		this.indexTab = new ArrayList<FdFunction>();
	}
	
	public final String getBaseName() {
		return lib;
	}
	
	public FdFunction getFunctionByIndex(int index) {
		return (index >= 0 && index < funcs.size()) ? funcs.get(index) : null;
	}
	
	public FdFunction[] getFunctions() {
		return funcs.toArray(FdFunction[]::new);
	}
	
	public Integer[] getBiases() {
		return biasMap.keySet().toArray(Integer[]::new);
	}
	
	public FdFunction getFunctionByBias(int bias) {
		return biasMap.getOrDefault(bias, null);
	}
	
	public String[] getFunctionNames() {
		return nameMap.keySet().toArray(String[]::new);
	}
	
	public boolean hasFunction(String name) {
		return nameMap.containsKey(name);
	}
	
	public FdFunction getFunctionByName(String name) {
		return nameMap.getOrDefault(name, null);
	}
	
	public void addFunction(FdFunction f) throws Exception {
		funcs.add(f);
		
		int bias = f.getBias();
		
		if (biasMap.containsKey(bias)) {
			throw new Exception(String.format("Bias %d already added!", bias));
		}
		
		biasMap.put(bias, f);
		
		String name = f.getName(false);
		nameMap.put(name, f);
		
		while (indexTab.size() < (Math.abs(bias) / 6)) {
			indexTab.add(null);
		}
		
		indexTab.set((Math.abs(bias) / 6) - 1, f);
	}
}
