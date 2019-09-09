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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import docking.widgets.OptionDialog;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import hunk.BinFmtHunk;
import hunk.BinImage;
import hunk.Reloc;
import hunk.Relocate;
import hunk.Relocations;
import hunk.Segment;
import hunk.SegmentType;
import structs.ExecLibrary;
import structs.InitData_Type;
import structs.InitTable;
import structs.Library;
import structs.Resident;

public class AmigaHunkLoader extends AbstractLibrarySupportLoader {

	static final String AMIGA_HUNK = "Amiga Executable Hunks loader";
	static final int DEF_IMAGE_BASE = 0x21F000;

	static final String OPTION_NAME = "ImageBase";
	Address imageBase = null;

	static final byte[] RTC_MATCHWORD = new byte[] { 0x4A, (byte) 0xFC };
	static final byte RTF_AUTOINIT = (byte) (1 << 7);

	@Override
	public String getName() {

		return AMIGA_HUNK;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (BinFmtHunk.isImageFile(new BinaryReader(provider, false))) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		FlatProgramAPI fpa = new FlatProgramAPI(program);
		Memory mem = program.getMemory();

		BinaryReader reader = new BinaryReader(provider, false);
		BinImage bi = BinFmtHunk.loadImage(reader, log);

		if (bi == null) {
			return;
		}

		Relocate rel = new Relocate(bi);
		long[] addrs = rel
				.getSeqAddresses((imageBase != null) ? imageBase.getOffset() : fpa.toAddr(DEF_IMAGE_BASE).getOffset());
		List<byte[]> datas = rel.relocate(addrs);

		Address startAddr = fpa.toAddr(addrs[0]);
		setFunction(fpa, startAddr, "start", log);

		for (Segment seg : bi.getSegments()) {
			long segOffset = addrs[seg.getId()];
			int size = seg.getSize();

			ByteArrayInputStream segBytes = new ByteArrayInputStream(datas.get(seg.getId()));

			if (segBytes.available() == 0) {
				continue;
			}

			boolean exec = seg.getType() == SegmentType.SEGMENT_TYPE_CODE;
			boolean write = seg.getType() == SegmentType.SEGMENT_TYPE_DATA;

			createSegment(segBytes, fpa, String.format("%s_%02d", seg.getType().toString(), seg.getId()), segOffset,
					size, write, exec, log);

			Segment[] toSegs = seg.getRelocationsToSegments();

			for (Segment toSeg : toSegs) {
				Relocations reloc = seg.getRelocations(toSeg);

				for (Reloc r : reloc.getRelocations()) {
					int dataOffset = r.getOffset();

					ByteBuffer buf = ByteBuffer.wrap(datas.get(seg.getId()));
					long newAddr = buf.getInt(dataOffset) + r.getAddend();

					try {
						mem.setBytes(fpa.toAddr(segOffset + dataOffset), intToBytes((int) newAddr));
					} catch (MemoryAccessException e) {
						log.appendException(e);
					}
				}
			}
		}
		
		createBaseSegment(fpa, log);

		analyzeResident(mem, fpa, startAddr, log);
	}

	private static byte[] intToBytes(int x) {
		ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
		buffer.order(ByteOrder.BIG_ENDIAN);
		buffer.putInt(x);
		return buffer.array();
	}

	private void analyzeResident(Memory mem, FlatProgramAPI fpa, Address startAddr, MessageLog log) {
		Program program = fpa.getCurrentProgram();

		try {
			while (true) {
				Address addr = fpa.find(startAddr, RTC_MATCHWORD);

				if (addr == null) {
					break;
				}

				long rt_MatchTag = mem.getInt(addr.add(2));

				startAddr = addr.add(2);
				if (addr.getOffset() != rt_MatchTag) {
					continue;
				}

				DataUtilities.createData(program, addr, (new Resident()).toDataType(), -1, false,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

				byte rt_Flags = mem.getByte(addr.add(10));

				if ((rt_Flags & RTF_AUTOINIT) == RTF_AUTOINIT) {
					long rt_Init = mem.getInt(addr.add(22));
					Address rt_InitAddr = fpa.toAddr(rt_Init);

					DataUtilities.createData(program, rt_InitAddr, (new InitTable()).toDataType(), -1, false,
							ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

					/* long it_DataSize = */mem.getInt(rt_InitAddr.add(0));
					long it_FuncTable = mem.getInt(rt_InitAddr.add(4));
					long it_DataInit = mem.getInt(rt_InitAddr.add(8));
					long it_InitFunc = mem.getInt(rt_InitAddr.add(12));

					Address it_InitFuncAddr = fpa.toAddr(it_InitFunc);
					setFunction(fpa, it_InitFuncAddr, String.format("it_InitFunc_%06X", addr.getOffset()),
							log);
					Function func = fpa.getFunctionAt(it_InitFuncAddr);
					func.setCustomVariableStorage(true);

					List<ParameterImpl> params = new ArrayList<>();
					
					Structure baseStruct = new StructureDataType("BaseLib", 0);
					baseStruct.add((new Library()).toDataType(), "base", null);
					baseStruct.add(WordDataType.dataType, "field0", null);

					params.add(new ParameterImpl("libBase", PointerDataType.dataType, program.getRegister("A6"), program));
					params.add(new ParameterImpl("seglist", PointerDataType.dataType, program.getRegister("A0"), program));
					params.add(new ParameterImpl("lib", new PointerDataType(baseStruct), program.getRegister("D0"), program));

					func.updateFunction(null, null, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS,
							params.toArray(ParameterImpl[]::new));

					if (it_DataInit != 0) {
						Address it_DataInitAddr = fpa.toAddr(it_DataInit);
						program.getSymbolTable().createLabel(it_DataInitAddr,
								String.format("it_DataInit_%06X", addr.getOffset()), SourceType.ANALYSIS);

						while (true) {
							InitData_Type tt;
							try {
								tt = new InitData_Type(mem, fpa, it_DataInitAddr.getOffset());
							} catch (Exception e) {
								break;
							}
							DataUtilities.createData(program, it_DataInitAddr, tt.toDataType(), -1, false,
									ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
							it_DataInitAddr = it_DataInitAddr.add(tt.toDataType().getLength());
						}
					}
					Address it_FuncTableAddr = fpa.toAddr(it_FuncTable);
					program.getSymbolTable().createLabel(it_FuncTableAddr,
							String.format("it_FuncTable_%06X", addr.getOffset()), SourceType.ANALYSIS);

					int i = 0;
					boolean askedForFd = false;
					FdLibFunctions funcTable = null;

					while (true) {
						long funcAddr = mem.getInt(it_FuncTableAddr.add(i * 4));

						Address funcAddr_ = fpa.toAddr(funcAddr);
						if (mem.contains(funcAddr_)) {
							if (!askedForFd && i >= 4) {
								TimeUnit.MILLISECONDS.sleep(400);
								if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null,
										"Question", "Do you have *_lib.fd file for this library?")) {
									String fdPath = showSelectFile("Select file...");
									funcTable = FdParser.readFdFile(fdPath);
								}
								askedForFd = true;
							}

							DataUtilities.createData(program, it_FuncTableAddr.add(i * 4), PointerDataType.dataType, -1,
									false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

							FdFunction funcDef = null;
							if (funcTable != null) {
								funcDef = funcTable.getFunctionByIndex(i - 4);
							}

							String name;

							switch (i) {
							case 0:
								name = "LIB_OPEN";
								break;
							case 1:
								name = "LIB_CLOSE";
								break;
							case 2:
								name = "LIB_EXPUNGE";
								break;
							case 3:
								name = "LIB_EXTFUNC";
								break;
							default:
								name = funcDef != null ? funcDef.getName(false) : String.format("LibFunc_%03d", i - 4);
							}

							setFunction(fpa, funcAddr_, name, log);
							func = fpa.getFunctionAt(funcAddr_);
							func.setCustomVariableStorage(true);

							params = new ArrayList<>();

							params.add(new ParameterImpl("base", new PointerDataType(baseStruct), program.getRegister("A6"),
									program));

							if (funcDef != null) {
								List<Map.Entry<String, String>> args = funcDef.getArgs();
								for (Entry<String, String> arg : args) {
									params.add(new ParameterImpl(arg.getKey(), DWordDataType.dataType,
											program.getRegister(arg.getValue()), program));
								}
							}

							func.updateFunction(null, null, FunctionUpdateType.CUSTOM_STORAGE, true,
									SourceType.ANALYSIS, params.toArray(ParameterImpl[]::new));
							i++;
						} else {
							break;
						}
					}
				}
			}
		} catch (InvalidInputException | MemoryAccessException | AddressOutOfBoundsException
				| CodeUnitInsertionException | DuplicateNameException | IOException | InterruptedException e) {
			log.appendException(e);
		}
	}

	private static String showSelectFile(String title) {
		JFileChooser jfc = new JFileChooser(new File("."));
		jfc.setDialogTitle(title);

		jfc.setFileFilter(new FileNameExtensionFilter("Functions Definition File", "fd"));
		jfc.setMultiSelectionEnabled(false);

		if (jfc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
			return jfc.getSelectedFile().getAbsolutePath();
		}

		return null;
	}

	private static void createBaseSegment(FlatProgramAPI fpa, MessageLog log) {
		MemoryBlock exec = createSegment(null, fpa, "EXEC", 0x4, 4, false, false, log);

		ExecLibrary lib = new ExecLibrary();

		try {
			Program program = fpa.getCurrentProgram();
			DataType dt = lib.toDataType();

			DataUtilities.createData(program, exec.getStart(), new PointerDataType(dt), -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

		} catch (DuplicateNameException | IOException | CodeUnitInsertionException e) {
			log.appendException(e);
		}
	}

	public static void setFunction(FlatProgramAPI fpa, Address address, String name, MessageLog log) {
		try {
			fpa.disassemble(address);
			fpa.createFunction(address, name);
			fpa.addEntryPoint(address);
			fpa.getCurrentProgram().getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	public static MemoryBlock createSegment(InputStream stream, FlatProgramAPI fpa, String name, long address,
			long size, boolean write, boolean execute, MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(true);
			block.setWrite(write);
			block.setExecute(execute);
			return block;
		} catch (Exception e) {
			log.appendException(e);
			return null;
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = new ArrayList<Option>();

		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		try {
			Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
			imageBase = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(DEF_IMAGE_BASE);
			list.add(new Option(OPTION_NAME, imageBase, Address.class, Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr"));
		} catch (LanguageNotFoundException e) {

		}

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		imageBase = null;

		for (Option option : options) {
			String optName = option.getName();
			try {
				if (optName.equals(OPTION_NAME)) {
					imageBase = (Address) option.getValue();

					long val = imageBase.getOffset();
					if (val >= 0x1000L && val <= 0x700000L) {
						break;
					}
				}
			} catch (Exception e) {
				if (e instanceof OptionException) {
					return e.getMessage();
				}
				return "Invalid value for " + optName + " - " + option.getValue();
			}
		}
		if (imageBase == null || (imageBase.getOffset() < 0x1000L) || (imageBase.getOffset() >= 0x700000L)) {
			return "Invalid image base";
		}

		return null;
	}
}
