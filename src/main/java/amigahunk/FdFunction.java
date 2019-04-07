package amigahunk;

import java.util.HashMap;
import java.util.stream.Collectors;

public class FdFunction {
	
	private final String name;
	private final int bias;
	private final boolean privat;
	private final int index;
	
	private HashMap<String, String> args;
	
	FdFunction(String name, int bias, boolean privat) {
		this.name = name;
		this.bias = bias;
		this.index = (bias - 6) / 6;
		this.privat = privat;
		
		args = new HashMap<String, String>();
	}

	public final String getName() {
		return name;
	}

	public final int getBias() {
		return bias;
	}
	
	public final int getIndex() {
		return index;
	}

	public final boolean isPrivat() {
		return privat;
	}
	
	public HashMap<String, String> getArgs() {
		return args;
	}
	
	public void addArg(String name, String reg) {
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
				sb.append(args.keySet().stream()
						.map(Object::toString)
						.collect(Collectors.joining(", ")));
			}
			
			sb.append(" )");
			return sb.toString();
		}
	}
}
