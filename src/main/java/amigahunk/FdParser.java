package amigahunk;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.framework.Application;

public class FdParser {

	public static FdFunctionTable readFdFile(String libName) {
		try {
			File f = new File(libName);
			
			if (!f.exists()) {
				f = new File("fd", libName);
				f = Application.getModuleDataFile(f.getPath()).getFile(false);
				
				if (!f.exists()) {
					return null;
				}
			}

			return readFd(f);
		} catch (Exception e) {
			return null;
		}
	}
	
	private static FdFunctionTable readFd(File f) throws Exception {
		final Pattern funcPat = Pattern.compile("([A-Za-z][_A-Za-z00-9]+)\\((.*)\\)\\((.*)\\)");
		
		FdFunctionTable funcTable = null;
		
		int bias = 0;
		boolean privat = true;
		
		BufferedReader reader;
		List<String> lines = new ArrayList<String>();
		
		reader = new BufferedReader(new FileReader(f));
		String _line = reader.readLine();
		while (_line != null) {
			lines.add(_line);
			_line = reader.readLine();
		}
		reader.close();
		
		for (String line : lines) {
			line = line.strip();
			
			if (line.length() > 1 && line.charAt(0) != '*') {
				// command
				if (line.charAt(0) == '#' && line.charAt(1) == '#') {
					String cmdLine = line.substring(2);
					String[] cmda = cmdLine.split(" ");
					String cmd = cmda[0];
					
					if (cmd.equals("base")) {
						funcTable = new FdFunctionTable(cmda[1]);
					} else if (cmd.equals("bias")) {
						bias = -1 * Integer.parseInt(cmda[1]);
					} else if (cmd.equals("private")) {
						privat = true;
					} else if (cmd.equals("public")) {
						privat = false;
					} else if (cmd.equals("end")) {
						break;
					} else {
						return null;
					}
				} else {
					Matcher m = funcPat.matcher(line);
					
					if (!m.matches()) {
						throw new Exception("Invalid FD format!");
					}
					
					String name = m.group(1);
					
					FdFunction func = new FdFunction(f.getName().toLowerCase(), name, bias, privat);
					
					if (func != null) {
						funcTable.addFunction(func);
					}
					
					String args = m.group(2);
					String regs = m.group(3);
					
					String[] arg = args.replaceAll(",", "/").split("/");
					String[] reg = regs.replaceAll(",", "/").split("/");
					
					if (arg.length != reg.length) {
						if (arg.length * 2 == reg.length) {
							arg = new String[reg.length];
							String[] argHi = (String[]) Arrays.asList(arg).stream()
									.map(e -> e + "_hi")
									.toArray();
							String[] argLo = (String[]) Arrays.asList(arg).stream()
									.map(e -> e + "_lo")
									.toArray();
							
							for (int i = 0; i < arg.length; i += 2) {
								arg[i] = argHi[i / 2];
								arg[i + 1] = argLo[i/ 2];
							}
						} else {
							throw new Exception("Reg and Arg name mismatch in FD file!");
						}
					}
					
					if (!arg[0].equals("")) {
						for (int i = 0; i < arg.length; ++i) {
							func.addArg(arg[i], reg[i]);
						}
					}
					
					bias -= 6;
				}
			}
		}
		
		return funcTable;
	}
}
