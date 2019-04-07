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

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AmigaHunkAnalyzer extends AbstractAnalyzer {
	
	private FdLibraryList libsList;
	
	public static boolean isAmigaHunkLoader(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(AmigaHunkLoader.AMIGA_HUNK);
	}

	public AmigaHunkAnalyzer() {
		super("Amiga Library Calls", "Analyses calls to system libraries", AnalyzerType.INSTRUCTION_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return isAmigaHunkLoader(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (isAmigaHunkLoader(program)) {
			libsList = new FdLibraryList();
			return true;
		}
		
		libsList = null;
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		
		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		System.out.println(set.contains(fpa.toAddr(0x0E)));
		SymbolicPropogator symEval = new SymbolicPropogator(program);
		symEval.setParamRefCheck(false);
		symEval.setReturnRefCheck(false);
		symEval.setStoredRefCheck(false);
		
		long totalNumAddresses = set.getNumAddresses();
		monitor.initialize(totalNumAddresses);

		try {
			InstructionIterator iterator = program.getListing().getInstructions(set, true);
			while (iterator.hasNext()) {
				Instruction instr = iterator.next();
				Address start = instr.getMinAddress();
				AddressSetView resultSet = flowConstants(program, start, set, symEval, monitor);
				if (resultSet != null) {
					if (!start.equals(set.getMinAddress())) {
						set = set.subtract(new AddressSet(set.getMinAddress(), start));
					}
					set = set.subtract(resultSet);
				}
			}
		} catch (CancelledException e) {

		}

		return false;
	}
	
	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		// follow all flows building up context
		// use context to fill out addresses on certain instructions
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
							context.setValue(reg, BigInteger.valueOf(libsList.getLibraryIndex(FdLibraryList.EXEC)));
						}
					} else if (mnemonic.equals("lea")) {
						Register destReg = instr.getRegister(1);
						if (destReg == null) {
							return false;
						}
						RegisterValue value = context.getRegisterValue(destReg);
						if (value != null) {
							BigInteger rval = value.getUnsignedValue();
							long lval = rval.longValue();
							Address refAddr = instr.getMinAddress().getNewAddress(lval);
							if ((lval > 4096 || lval < 0) &&
								program.getMemory().contains(refAddr) ||
								Arrays.asList(instr.getOpObjects(0)).contains(
									program.getRegister("PC"))) {
								Memory memory = program.getMemory();
								AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
								ByteProvider provider = new MemoryByteProvider(memory, space);
								BinaryReader reader = new BinaryReader(provider, false);
								try {
									String libName = reader.readAsciiString(refAddr.getOffset()).replace(".library", "_lib.fd");
									context.setValue(context.getRegister("A6"), BigInteger.valueOf(libsList.getLibraryIndex(libName)));
								} catch (IOException e) {
									
								}
							}
						}
					} else if (mnemonic.equals("jsr")) {
						Object[] objs = instr.getOpObjects(0);
						Register reg = instr.getRegister(1);
						if (reg != null && reg.getName().equals("A6") &&
								objs.length != 0 && (objs[0] instanceof Scalar)) {
							String libName = libsList.getLibraryByIndex(context.getValue(reg, false).intValue());
							FdFunctionTable fd = FdParser.readFdFile(libName);
							
							if (fd == null) {
								return false;
							}
							
							FdFunction func = fd.getFuncByBias((int)((Scalar)objs[0]).getSignedValue());
							
							if (func == null) {
								return false;
							}
							
							if (func.getName().equals("OpenLibrary")) {
								RegisterValue val = context.getRegisterValue(context.getRegister("A0"));
								System.out.print(val);
							}
							
							program.getListing().setComment(instr.getAddress(), CodeUnit.EOL_COMMENT, func.getArgsStr(true));
						}
					}
					return false;
				}
			};

		return symEval.flowConstants(flowStart, flowSet, eval, true, monitor);
	}
}
