package amigahunk;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

public class FdFunction {
	
	private final String lib;
	private final String name;
	private final int bias;
	private final boolean privat;
	private final int index;
	
	private Map<String, String> args;
	
	public static final String LIB_SPLITTER = "->";
	
	public FdFunction(String lib, String name, int bias, boolean privat) {
		this.lib = lib;
		this.name = name;
		this.bias = bias;
		this.index = (bias - 6) / 6;
		this.privat = privat;
		
		args = new HashMap<>();
	}
	
	public final String getLib() {
		return lib;
	}

	public final String getName(boolean withLib) {
		return (withLib ? lib.replace("_lib.fd", "") + LIB_SPLITTER : "") + name;
	}

	public final int getBias() {
		return bias;
	}
	
	public final int getIndex() {
		return index;
	}

	public final boolean isPrivate() {
		return privat;
	}
	
	public Map<String, String> getArgs() {
		return args;
	}
	
	public void addArg(String name, String reg) {
		name = name.replace(" ", "").replace("*", "");
		
		if (args.containsKey(name)) {
			name = String.format("%s%d", name, args.size());
		}
		
		args.put(name, reg);
	}
	
	public String getArgsStr(boolean withReg) {
		if (args.size() == 0) {
			return "";
		} else {
			StringBuilder sb = new StringBuilder();
			sb.append("( ");
			
			if (withReg) {
				sb.append(args.entrySet().stream()
						.map(e -> e.getKey() + "/" + e.getValue())
						.collect(Collectors.joining(", ")));
			} else {
				sb.append(args.entrySet().stream()
						.map(Object::toString)
						.collect(Collectors.joining(", ")));
			}
			
			sb.append(" )");
			return sb.toString();
		}
	}
	
	public Register[] getArgRegs(Program program) {
		if (args.size() == 0) {
			return new Register[] {};
		} else {
			return args.entrySet().stream()
					.map(e -> new Register(program.getRegister(e.getValue()))).toArray(Register[]::new);
		}
	}
}
