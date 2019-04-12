package amigahunk;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import ghidra.framework.Application;

public class FdFunctionsList {
	
	private HashSet<FdFunction> funcsList;
	private HashSet<String> libsList;
	
	private void initList() {
		funcsList = new HashSet<FdFunction>();
		libsList = new HashSet<String>();
		
		try {
			File dir = Application.getModuleDataSubDirectory("fd").getFile(false);
			
			for (final File entry : dir.listFiles()) {
				String fname = entry.getName().toLowerCase();
				libsList.add(fname);
				FdFunctionTable fd = FdParser.readFdFile(fname);
				
				if (fd == null) {
					continue;
				}
				
				funcsList.addAll(Arrays.asList(fd.getFuncs()));
		    }
		} catch (IOException e) {
			
		}
	}
	
	FdFunctionsList() {
		initList();
	}
	
	public String[] getLibsList() {
		return libsList.toArray(String[]::new);
	}
	
	public FdFunction[] getFunctionsByBias(List<String> filter, int bias) {
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
}
