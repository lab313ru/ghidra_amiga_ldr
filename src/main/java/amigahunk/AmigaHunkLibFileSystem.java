package amigahunk;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderInputStream;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.FileSystemRefManager;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import hunk.HunkBlock;
import hunk.HunkBlockFile;
import hunk.HunkBlockType;
import hunk.HunkIndexBlock;
import hunk.HunkIndexHunkEntry;
import hunk.HunkIndexSymbolDef;
import hunk.HunkIndexSymbolRef;
import hunk.HunkIndexUnitEntry;
import hunk.HunkLibBlock;
import hunk.HunkNameBlock;
import hunk.HunkParseError;
import hunk.HunkType;
import hunk.HunkUnitBlock;

@FileSystemInfo(
		type = "amigahunklibfile",
		description = "Amiga Hunk Library File",
		factory = AmigaHunkLibFileSystem.AmigaHunkLibFileSystemFactory.class)
public class AmigaHunkLibFileSystem implements GFileSystem {

	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<LibHunkItem> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);

	private ByteProvider provider;

	/**
	 * File system constructor.
	 * 
	 * @param fsFSRL The root {@link FSRL} of the file system.
	 * @param provider The file system provider.
	 */
	public AmigaHunkLibFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	/**
	 * Mounts (opens) the file system.
	 * 
	 * @param monitor A cancellable task monitor.
	 */
	public void mount(TaskMonitor monitor) {
		monitor.setMessage("Opening " + AmigaHunkLibFileSystem.class.getSimpleName() + "...");

		BinaryReader reader = new BinaryReader(provider, false);
		
		try {
			HunkBlockFile hbf = new HunkBlockFile(reader);
			hbf.load();
			
			Iterator<Map.Entry<Long, HunkBlock>> hunkBlocks = hbf.getHunkBlocks().entrySet().iterator();
			
			String rootDir = "";
			int index = 0;
			
			while (hunkBlocks.hasNext()) {
				Map.Entry<Long, HunkBlock> block = hunkBlocks.next();
				
				HunkBlock bb = block.getValue();
				HunkType type = bb.getHunkType();
				
				LibHunkItem item = new LibHunkItem();
				item.offset = block.getKey() + 4;
				item.name = String.format("%03d_%s", fsih.getFileCount() + 1, bb.getHunkType());
				item.size = bb.getSize();
				
				switch (type) {
				case HUNK_UNIT: {
					index = 0;
					Map.Entry<Long, HunkBlock> nameBlock = hunkBlocks.next();
					HunkNameBlock name = (HunkNameBlock)nameBlock.getValue();
					System.out.println(name.getName());
				} break;
				case HUNK_END:
					continue;
				case HUNK_LIB: {
					SortedMap<Long, HunkBlock> libBlocks = ((HunkLibBlock)bb).getHunkBlocks();
					
					for (Map.Entry<Long, HunkBlock> libBlock : libBlocks.entrySet()) {
						HunkBlock libB = libBlock.getValue();
						
						LibHunkItem libItem = new LibHunkItem();
						libItem.name = String.format("%03d_%s", fsih.getFileCount() + 1, libB.getHunkType());
						libItem.offset = libBlock.getKey() + 4;
						libItem.size = libB.getSize();

						fsih.storeFile(String.format("%s/%s", item.name, libItem.name), fsih.getFileCount(), false, libItem.size, libItem);
					}
				} break;
				case HUNK_INDEX: {
					byte[] strtab = ((HunkIndexBlock)bb).getStrtab();
					
					HunkIndexUnitEntry[] units = ((HunkIndexBlock)bb).getHunkIndexUnitEntries();
					
					for (HunkIndexUnitEntry unit : units) {
						System.out.println(String.format("Unit:\n\t%s - %d",
								unit.getName(),
								unit.getFirstHunkLongOff()
								));
						
						//LibHunkItem libItem = new LibHunkItem();
						
						HunkIndexHunkEntry[] hunkEntries = unit.getHunkIndexHunkEntries();
						
						for (HunkIndexHunkEntry hunkEntry : hunkEntries) {
							System.out.println(String.format("\tEntry:\n\t\t%s - %d - %d",
									hunkEntry.getName(),
									hunkEntry.getHunkLongs(),
									hunkEntry.getHunkCtype()
									));
							
							HunkIndexSymbolDef[] symDefs = hunkEntry.getSymDefs();
							
							for (HunkIndexSymbolDef symDef : symDefs) {
								System.out.println(String.format("\t\tSymDef:\n\t\t\t%s - %d - %d",
										symDef.getName(),
										symDef.getValue(),
										symDef.getSymCtype()
										));
							}
							
							HunkIndexSymbolRef[] symRefs = hunkEntry.getSymRefs();
							
							for (HunkIndexSymbolRef symRef : symRefs) {
								System.out.println(String.format("\t\tSymRef:\n\t\t\t%s",
										symRef.getName()
										));
							}
						}
					}
				} break;
				default:
					fsih.storeFile(String.format("%s/%s", rootDir, item.name), fsih.getFileCount(), false, item.size, item);
					break;
				}
			}
			
		} catch (HunkParseError e) {
			return;
		}
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (provider != null) {
			provider.close();
			provider = null;
		}
		fsih.clear();
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public int getFileCount() {
		return fsih.getFileCount();
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		// TODO: Get an input stream for a file.  The following is an example of how the metadata
		// might be used to get an input stream from a stored provider offset.
		LibHunkItem metadata = fsih.getMetadata(file);
		return (metadata != null)
				? new ByteProviderInputStream(provider, metadata.offset, metadata.size)
				: null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		LibHunkItem metadata = fsih.getMetadata(file);
		return (metadata == null) ? null : FSUtilities.infoMapToString(getInfoMap(metadata));
	}

	public Map<String, String> getInfoMap(LibHunkItem metadata) {
		Map<String, String> info = new LinkedHashMap<>();

		info.put("Name", metadata.name);
		info.put("Size", "0x" + Long.toHexString(metadata.size));
		return info;
	}

	// TODO: Customize for the real file system.
	public static class AmigaHunkLibFileSystemFactory
			implements GFileSystemFactoryFull<AmigaHunkLibFileSystem>, GFileSystemProbeFull {

		@Override
		public AmigaHunkLibFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
				ByteProvider byteProvider, File containerFile, FileSystemService fsService,
				TaskMonitor monitor) throws IOException, CancelledException {

			AmigaHunkLibFileSystem fs = new AmigaHunkLibFileSystem(targetFSRL, byteProvider);
			fs.mount(monitor);
			return fs;
		}

		@Override
		public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
				FileSystemService fsService, TaskMonitor monitor)
				throws IOException, CancelledException {

			BinaryReader reader = new BinaryReader(byteProvider, false);
			
			try {
				HunkBlockFile hbf = new HunkBlockFile(reader);
				HunkBlockType type = hbf.getHunkBlockType();
				return (type == HunkBlockType.TYPE_LIB) /*|| (type == HunkBlockType.TYPE_UNIT)*/;
			} catch (HunkParseError e) {
				return false;
			}
		}
	}

	private static class LibHunkItem {
		private String name;
		private long offset;
		private long size;
	}

}
