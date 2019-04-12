/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package amigahunk;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AmigaHunkAnalyzer extends AbstractAnalyzer {
	
	private final List<String> filter = new ArrayList<String>();
	private FdFunctionsList funcsList;
	
	public static boolean isAmigaHunkLoader(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(AmigaHunkLoader.AMIGA_HUNK);
	}

	public AmigaHunkAnalyzer() {
		super("Amiga Library Calls", "Analyses calls to system libraries", AnalyzerType.INSTRUCTION_ANALYZER);
		
		filter.add("exec_lib.fd");
		filter.add("dos_lib.fd");
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return isAmigaHunkLoader(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (isAmigaHunkLoader(program)) {
			funcsList = new FdFunctionsList();
			return true;
		}
		
		funcsList = null;
		return false;
	}
	
	@Override
	public void registerOptions(Options options, Program program) {
		
		if (funcsList == null) {
			return;
		}
		
		String[] libsList = funcsList.getLibsList();
		for (String lib : libsList) {
			boolean val = (filter != null) ? filter.contains(lib) : true;
			options.registerOption(lib.replace("_lib.fd", "").toUpperCase(), val, null, String.format("Analyze calls from %s", lib));
		}
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		
		if (funcsList == null) {
			return;
		}
		
		filter.clear();
		
		String[] libsList = funcsList.getLibsList();
		for (String lib : libsList) {
			if (!options.getBoolean(lib.replace("_lib.fd", "").toUpperCase(), true)) {
				filter.remove(lib);
			} else {
				filter.add(lib);
			}
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		
		SymbolicPropogator symEval = new SymbolicPropogator(program);
		symEval.setParamRefCheck(false);
		symEval.setReturnRefCheck(false);
		symEval.setStoredRefCheck(false);
		
		monitor.setMessage("Analysing library calls...");

		try {
			flowConstants(program, set.getMinAddress(), set, symEval, monitor);
		} catch (CancelledException e) {

		}

		return true;
	}
	
	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		ConstantPropagationContextEvaluator eval =
			new ConstantPropagationContextEvaluator(true) {
				@Override
				public boolean evaluateContext(VarnodeContext context, Instruction instr) {
					String mnemonic = instr.getMnemonicString();

					if (mnemonic.equals("movea.l")) {
						Object[] objs = instr.getOpObjects(0);
						Register reg = instr.getRegister(1);
						
						if (reg != null && reg.getName().equals("A6") &&
							objs.length != 0 && (objs[0] instanceof Address) &&
							((Address)objs[0]).getOffset() == 4) {
							program.getListing().setComment(instr.getAddress(), CodeUnit.PRE_COMMENT, "EXEC.library Base offset");
						}
					} else if (mnemonic.equals("jsr")) {
						Object[] objs = instr.getOpObjects(0);
						Register reg = instr.getRegister(1);
						if (reg != null && reg.getName().equals("A6") &&
								objs.length != 0 && (objs[0] instanceof Scalar)) {
							FdFunction[] funcs = funcsList.getFunctionsByBias(filter, (int)((Scalar)objs[0]).getSignedValue());
							
							StringBuilder sb = new StringBuilder();
							
							for (FdFunction func : funcs) {
								sb.append(func.getName());
								sb.append(func.getArgsStr(true));
								sb.append(System.getProperty("line.separator"));
							}

							program.getListing().setComment(instr.getAddress(), CodeUnit.PRE_COMMENT, sb.toString().strip());
						}
					}
					return false;
				}
			};

		return symEval.flowConstants(flowStart, flowSet, eval, true, monitor);
	}
}
