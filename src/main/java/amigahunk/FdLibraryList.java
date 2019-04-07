package amigahunk;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.framework.Application;

public class FdLibraryList {

	public static final String EXEC = "exec_lib.fd";
	
	private HashMap<String, Integer> libsList;
	
	private void initList() {
		libsList = new HashMap<String, Integer>();
		
		try {
			int index = 0;
			File dir = Application.getModuleDataSubDirectory("fd").getFile(false);
			
			for (final File entry : dir.listFiles()) {
				libsList.put(entry.getName().toLowerCase(), index++);
		    }
		} catch (IOException e) {
			
		}
	}
	
	FdLibraryList() {
		initList();
	}
	
	public int getLibraryIndex(String libName) {
		libName = libName.toLowerCase();

		return libsList.getOrDefault(libName, -1);
	}
	
	public String getLibraryByIndex(int index) {
		for (Map.Entry<String, Integer> entry : libsList.entrySet()) {
			if (entry.getValue() == index) {
				return entry.getKey();
			}
		}
		
		return null;
	}
}
