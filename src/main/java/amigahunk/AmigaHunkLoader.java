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
import ghidra.app.plugin.core.reloc.InstructionStasher;
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
import ghidra.program.model.data.DataTypeConflictHandler;
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
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import hunk.BinFmtHunk;
import hunk.BinImage;
import hunk.HunkBlockFile;
import hunk.HunkBlockType;
import hunk.HunkParseError;
import hunk.Reloc;
import hunk.Relocate;
import hunk.Segment;
import hunk.SegmentType;
import hunk.XDefinition;
import hunk.XReference;
import structs.ExecLibrary;
import structs.InitData_Type;
import structs.InitTable;
import structs.Library;
import structs.Message;
import structs.Resident;
import structs.WBArg;
import structs.WBStartup;

public class AmigaHunkLoader extends AbstractLibrarySupportLoader {

	static final String AMIGA_HUNK = "Amiga Executable Hunks loader";
	public static final int DEF_IMAGE_BASE = 0x21F000;

	static final String OPTION_NAME = "ImageBase";
	public static Address imageBase = null;

	static final byte[] RTC_MATCHWORD = new byte[] { 0x4A, (byte) 0xFC };
	static final byte RTF_AUTOINIT = (byte) (1 << 7);

	static final String refsSegmName = "REFS";
	static int refsLastIndex = 0;

	@Override
	public String getName() {

		return AMIGA_HUNK;
	}
	
	public static int getImageBase(int offset) {
		return (int) (((imageBase != null) ? imageBase.getOffset() : DEF_IMAGE_BASE) + offset);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (HunkBlockFile.isHunkBlockFile(new BinaryReader(provider, false))) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		FlatProgramAPI fpa = new FlatProgramAPI(program);
		Memory mem = program.getMemory();

		BinaryReader reader = new BinaryReader(provider, false);
		HunkBlockType type = HunkBlockFile.peekType(reader);
		HunkBlockFile hbf = new HunkBlockFile(reader, type == HunkBlockType.TYPE_LOADSEG);
		
		switch (type) {
		case TYPE_LOADSEG: 
		case TYPE_UNIT: {
			try {
				loadExecutable(imageBase, type == HunkBlockType.TYPE_LOADSEG, hbf, fpa, mem, log);
			} catch (Throwable e) {
				e.printStackTrace();
				log.appendException(e);
			}
		} break;
		case TYPE_LIB: {
			
		} break;
		default: {
			
		} break;
		}
	}

	private static void loadExecutable(Address imageBase, boolean isExecutable, HunkBlockFile hbf, FlatProgramAPI fpa, Memory mem, MessageLog log) throws Throwable {
		BinImage bi = BinFmtHunk.loadImage(hbf, log);
		
		if (bi == null) {
			return;
		}
		
		int _imageBase = getImageBase(0);

		Relocate rel = new Relocate(bi);
		int[] addrs = rel.getSeqAddresses(_imageBase);
		List<byte[]> datas;
		try {
			datas = rel.relocate(addrs);
		} catch (HunkParseError e1) {
			log.appendException(e1);
			return;
		}
		
		int lastSectAddress = 0;

		for (Segment seg : bi.getSegments()) {
			int segOffset = addrs[seg.getId()];
			int size = seg.getSize();
			
			if (segOffset + size > lastSectAddress) {
				lastSectAddress = segOffset + size;
			}

			ByteArrayInputStream segBytes = new ByteArrayInputStream(datas.get(seg.getId()));

			if (segBytes.available() == 0) {
				continue;
			}

			boolean exec = seg.getType() == SegmentType.SEGMENT_TYPE_CODE;
			boolean write = seg.getType() == SegmentType.SEGMENT_TYPE_DATA;

			createSegment(segBytes, fpa, seg.getName(), segOffset, size, write, exec, log);
			relocateSegment(seg, segOffset, datas, mem, fpa, log);
		}
		
		for (Segment seg : bi.getSegments()) {
			int segOffset = addrs[seg.getId()];

			applySegmentDefs(seg, segOffset, fpa, fpa.getCurrentProgram().getSymbolTable(), log, lastSectAddress);
		}
		
		Address startAddr = fpa.toAddr(addrs[0]);
		
		createBaseSegment(fpa, log);

		analyzeResident(mem, fpa, startAddr, log);
		
		addCustomTypes(fpa.getCurrentProgram(), log);
		
		if (isExecutable) {
			setFunction(fpa, startAddr, "start", log);
		}
	}
	
	private static void addCustomTypes(Program program, MessageLog log) {
		try {
			program.getDataTypeManager().addDataType((new Message()).toDataType(), DataTypeConflictHandler.DEFAULT_HANDLER);
			program.getDataTypeManager().addDataType((new WBArg()).toDataType(), DataTypeConflictHandler.DEFAULT_HANDLER);
			program.getDataTypeManager().addDataType((new WBStartup()).toDataType(), DataTypeConflictHandler.DEFAULT_HANDLER);
		} catch (DuplicateNameException | IOException e) {
			log.appendException(e);
		}
	}
	
	private static void relocateSegment(Segment seg, int segOffset, final List<byte[]> datas, Memory mem, FlatProgramAPI fpa, MessageLog log) {
		Segment[] toSegs = seg.getRelocationsToSegments();

		for (Segment toSeg : toSegs) {
			Reloc[] reloc = seg.getRelocations(toSeg);

			for (Reloc r : reloc) {
				int dataOffset = r.getOffset();

				ByteBuffer buf = ByteBuffer.wrap(datas.get(seg.getId()));
				int newAddr = 0;
				
				try {
					switch (r.getWidth()) {
					case 4:
						newAddr = buf.getInt(dataOffset) + r.getAddend();
						break;
					case 2:
						newAddr = buf.getShort(dataOffset) + r.getAddend();
						break;
					case 1:
						newAddr = buf.get(dataOffset) + r.getAddend();
						break;
					}
					patchReference(mem, fpa.toAddr(segOffset + dataOffset), newAddr, r.getWidth());
				} catch (MemoryAccessException | CodeUnitInsertionException e) {
					log.appendException(e);
					return;
				}
			}
		}
	}
	
	private static void applySegmentDefs(Segment seg, int segOffset, FlatProgramAPI fpa, SymbolTable st, MessageLog log, int lastSectAddress) throws Throwable {
		if (seg.getSegmentInfo().getDefinitions() == null) {
			return;
		}
		
		for (final XDefinition entry : seg.getSegmentInfo().getDefinitions()) {
			Address defAddr = fpa.toAddr(entry.getOffset());
			
			if (!entry.isAbsolute()) {
				defAddr = fpa.toAddr(segOffset + entry.getOffset());
			}
			
			st.createLabel(defAddr, entry.getName(), SourceType.USER_DEFINED);
			
			if (entry.getName().equals("___startup")) {
				setFunction(fpa, defAddr, entry.getName(), log);
			}
		}
		
		if (seg.getSegmentInfo().getReferences() == null) {
			return;
		}

		Memory mem = fpa.getCurrentProgram().getMemory();
		
		for (final XReference entry : seg.getSegmentInfo().getReferences()) {
			for (Integer offset : entry.getOffsets()) {
				Address fromAddr = fpa.toAddr(segOffset + offset);
				int newAddr = 0;
				
				switch (entry.getType()) {
				case R_ABS: {
					newAddr = addReference(mem, fpa, st, entry.getName(), lastSectAddress);
					patchReference(mem, fromAddr, newAddr, entry.getWidth());
				} break;
				case R_SD: {
					newAddr = addReference(mem, fpa, st, entry.getName(), lastSectAddress);
					patchReference(mem, fromAddr, (int) (newAddr - lastSectAddress), entry.getWidth());
				} break;
				case R_PC: {
					newAddr = addReference(mem, fpa, st, entry.getName(), lastSectAddress);
					patchReference(mem, fromAddr, (int) (newAddr - fromAddr.getOffset()), entry.getWidth());
				} break;
				}
				
			}
		}
	}
	
	private static void patchReference(Memory mem, Address fromAddr, int toAddr, int width) throws MemoryAccessException, CodeUnitInsertionException {
		InstructionStasher instructionStasher = new InstructionStasher(mem.getProgram(), fromAddr);
		switch (width) {
		case 4:
			mem.setBytes(fromAddr, intToBytes(toAddr));
			break;
		case 2:
			mem.setBytes(fromAddr, shortToBytes((short) toAddr));
			break;
		case 1:
			mem.setBytes(fromAddr, new byte[] {(byte) toAddr});
			break;
		}
		instructionStasher.restore();
	}

	private static int addReference(Memory mem, FlatProgramAPI fpa, SymbolTable st, String name, int lastSectAddress) throws Throwable {
		MemoryBlock block = mem.getBlock(refsSegmName);
		
		if (block == null) {
			block = mem.createUninitializedBlock(refsSegmName, fpa.toAddr(lastSectAddress), 0x1000L, false);
		}
		
		List<Symbol> syms = st.getGlobalSymbols(name);
		if (syms.size() > 0) {
			return (int) syms.get(0).getAddress().getOffset();
		}
		
		Address newAddress = block.getStart().add(refsLastIndex * 4);
		st.createLabel(newAddress, name, SourceType.IMPORTED);
		refsLastIndex++;
		
		return (int) newAddress.getOffset();
	}

	private static byte[] intToBytes(int x) {
		ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
		buffer.order(ByteOrder.BIG_ENDIAN);
		buffer.putInt(x);
		return buffer.array();
	}
	
	private static byte[] shortToBytes(short x) {
		ByteBuffer buffer = ByteBuffer.allocate(Short.BYTES);
		buffer.order(ByteOrder.BIG_ENDIAN);
		buffer.putShort(x);
		return buffer.array();
	}

	private static void analyzeResident(Memory mem, FlatProgramAPI fpa, Address startAddr, MessageLog log) {
		Program program = fpa.getCurrentProgram();
		ReferenceManager refMgr = program.getReferenceManager();

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
					setFunction(fpa, it_InitFuncAddr, String.format("it_InitFunc_%06X", addr.getOffset()), log);
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
					
					boolean isRelative = (mem.getShort(it_FuncTableAddr) & 0xFFFF) == 0xFFFF;

					while (true) {
						long funcAddr;
						
						if (isRelative) {
							short relVal = mem.getShort(it_FuncTableAddr.add((i + 1) * 2));
							
							if ((relVal & 0xFFFF) == 0xFFFF) {
								break;
							}
							
							funcAddr = it_FuncTableAddr.add(relVal).getOffset();
						} else {
							funcAddr = mem.getInt(it_FuncTableAddr.add(i * 4));
						}
						
						Address funcAddr_ = fpa.toAddr(funcAddr);
						if (!mem.contains(funcAddr_)) {
							break;
						}

						if (!askedForFd && i >= 4) {
							TimeUnit.SECONDS.sleep(1);
							if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null,
									"Question", String.format("Do you have *%s file for this library?", FdParser.LIB_FD_EXT))) {
								String fdPath = showSelectFile("Select file...");
								funcTable = FdParser.readFdFile(fdPath);
							}
							askedForFd = true;
						}

						if (isRelative) {
							DataUtilities.createData(program, it_FuncTableAddr.add((i + 1) * 2), WordDataType.dataType, -1,
									false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
							refMgr.addMemoryReference(it_FuncTableAddr.add((i + 1) * 2), funcAddr_, RefType.DATA, SourceType.ANALYSIS, 0);
						} else {
							DataUtilities.createData(program, it_FuncTableAddr.add(i * 4), PointerDataType.dataType, -1,
									false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
						}

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

						params.add(new ParameterImpl("base", new PointerDataType(baseStruct), program.getRegister("A6"), program));

						if (funcDef != null) {
							List<Map.Entry<String, String>> args = funcDef.getArgs();
							for (Entry<String, String> arg : args) {
								params.add(new ParameterImpl(arg.getKey(), PointerDataType.dataType,
										program.getRegister(arg.getValue()), program));
							}
						}

						func.updateFunction(null, null, FunctionUpdateType.CUSTOM_STORAGE, true,
								SourceType.ANALYSIS, params.toArray(ParameterImpl[]::new));
						i++;
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

		try {
			Program program = fpa.getCurrentProgram();

			DataUtilities.createData(program, exec.getStart(), new PointerDataType((new ExecLibrary()).toDataType()), -1, false,
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
		if (imageBase == null || (imageBase.getOffset() < 0x1000L) || (imageBase.getOffset() >= 0x80000000L)) {
			return "Invalid image base";
		}

		return null;
	}
}
