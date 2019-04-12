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
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import hunk.BinFmtHunk;
import hunk.BinImage;
import hunk.Reloc;
import hunk.Relocate;
import hunk.Relocations;
import hunk.Segment;
import hunk.SegmentType;

public class AmigaHunkLoader extends AbstractLibrarySupportLoader {

	static final String AMIGA_HUNK = "Amiga Executable Hunks loader";
	static final int DEF_IMAGE_BASE = 0x21F000;
	
	static final String OPTION_NAME = "ImageBase";
	Address imageBase = null;
	
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
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws IOException {
		
		FlatProgramAPI fpa = new FlatProgramAPI(program);

		BinaryReader reader = new BinaryReader(provider, false);
		BinImage bi = BinFmtHunk.loadImage(reader, log);
		
		if (bi == null) {
			return;
		}
		
		Relocate rel = new Relocate(bi);
		long[] addrs = rel.getSeqAddresses((imageBase != null) ? imageBase.getOffset() : fpa.toAddr(DEF_IMAGE_BASE).getOffset());
		List<byte[]> datas = rel.relocate(addrs);

		setFunction(program, fpa, fpa.toAddr(addrs[0]), "start", log);
		
		RelocationTable relocTable = program.getRelocationTable();

		for (Segment seg : bi.getSegments()) {
			long segOffset = addrs[seg.getId()];
			int size = seg.getSize();
			
			Segment[] toSegs = seg.getRelocationsToSegments();
			
			for (Segment toSeg : toSegs) {
				Relocations reloc = seg.getRelocations(toSeg);
				
				for (Reloc r : reloc.getRelocations()) {
					int dataOffset = r.getOffset();
					
					ByteBuffer buf = ByteBuffer.wrap(datas.get(seg.getId()));
					long newAddr = segOffset + buf.getInt(dataOffset) + r.getAddend();
					
					long[] values = new long[1];
					values[0] = newAddr;
					relocTable.add(fpa.toAddr(segOffset + dataOffset), r.getWidth(), values, null, null);
				}
			}
			
			ByteArrayInputStream segBytes = new ByteArrayInputStream(datas.get(seg.getId()));
			
			boolean exec = seg.getType() == SegmentType.SEGMENT_TYPE_CODE;
			boolean write = seg.getType() == SegmentType.SEGMENT_TYPE_DATA;
			
			createSegment(segBytes, fpa, String.format("%s_%02d", seg.getType().toString(), seg.getId()), segOffset, size, write, exec, log);
		}
		
//		try {
//			program.setImageBase(fpa.toAddr(DEF_IMAGE_BASE), true);
//		} catch (AddressOverflowException | LockException | IllegalStateException e) {
//			log.appendException(e);
//		}
	}
	
	private static void setFunction(Program program, FlatProgramAPI fpa, Address address, String name, MessageLog log) {
		try {
			fpa.disassemble(address);
			fpa.createFunction(address, name);
			fpa.addEntryPoint(address);
			program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
	
	private static void createSegment(InputStream stream, FlatProgramAPI fpa, String name, long address, long size, boolean write, boolean execute, MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(true);
			block.setWrite(write);
			block.setExecute(execute);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =	new ArrayList<Option>();
		
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
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

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
			}
			catch (Exception e) {
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
