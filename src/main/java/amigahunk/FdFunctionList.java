package amigahunk;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import ghidra.framework.Application;

public class FdFunctionList {
	
	private HashSet<FdFunction> funcsList;
	private HashSet<String> libsList;
	private HashMap<String, FdFunctionTable> libFuncs;
	
	private void initList() {
		funcsList = new HashSet<>();
		libsList = new HashSet<>();
		libFuncs = new HashMap<>();
		
		try {
			File dir = Application.getModuleDataSubDirectory("fd").getFile(false);
			
			for (final File entry : dir.listFiles()) {
				String fname = entry.getName().toLowerCase();
				libsList.add(fname);
				FdFunctionTable fd = FdParser.readFdFile(fname);
				
				libFuncs.put(fname, fd);
				
				if (fd == null) {
					continue;
				}
				
				funcsList.addAll(Arrays.asList(fd.getFunctions()));
		    }
		} catch (IOException e) {
			
		}
	}
	
	FdFunctionList() {
		initList();
	}
	
	public String[] getLibsList() {
		return libsList.toArray(String[]::new);
	}
	
	public FdFunction[] getLibsFunctionsByBias(List<String> filter, int bias) {
		List<FdFunction> l = new ArrayList<FdFunction>();
		
		for (FdFunction entry : funcsList) {
			if (filter == null || !filter.contains(entry.getLib().toLowerCase())) {
				continue;
			}
			
			if (entry.getBias() == bias) {
				l.add(entry);
			}
		}
		
		return l.toArray(FdFunction[]::new);
	}
	
	public FdFunction[] getFunctionsByLibs(List<String> filter) {
		List<FdFunction> l = new ArrayList<FdFunction>();
		
		for (FdFunction entry : funcsList) {
			if (filter == null || !filter.contains(entry.getLib().toLowerCase())) {
				continue;
			}
			
			l.add(entry);
		}
		
		return l.toArray(FdFunction[]::new);
	}
	
	public FdFunctionTable getFunctionTableByLib(String lib) {
		return libFuncs.getOrDefault(lib, null);
	}
}
