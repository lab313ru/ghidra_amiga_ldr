package amigahunk;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import generic.stl.Pair;
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
import hunk.HunkNameBlock;
import hunk.HunkParseError;
import hunk.HunkType;
import hunk.HunkUnitBlock;
import hunk.HunkLibBlock;
import hunk.HunkIndexUnitEntry;
import hunk.HunkIndexBlock;
import hunk.HunkIndexHunkEntry;
import hunk.HunkIndexSymbolDef;
import hunk.HunkIndexSymbolRef;

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
			HunkBlockFile hbf = new HunkBlockFile(reader, false);
			
			String unitName = null, lastName = "";
			int unitOffset = 0;
			int unitSize = 0;
			int[] firstLibUnitOffset = {-1};
			HunkLibBlock libBlock = null;
			
			final List<Pair<Integer, HunkBlock>> blocks = hbf.getHunkBlocks();
			
			for (int i = 0; i < blocks.size(); ++i) {
				HunkBlock bb = blocks.get(i).second;
				HunkType type = bb.getHunkType();
				int hunkOffset = blocks.get(i).first;
				
				switch (type) {
				case HUNK_UNIT: {
					unitOffset = hunkOffset;
					unitSize = bb.getSize();
					unitName = ((HunkUnitBlock)bb).getName();
					System.out.println(unitName);
				} break;
				case HUNK_LIB: {
					for (Pair<Integer, HunkBlock> block : ((HunkLibBlock)bb).getHunkBlocks()) {
						if (firstLibUnitOffset[0] == -1) {
							firstLibUnitOffset[0] = block.first;
						}
						
						System.out.println(String.format("0x%08X - %s", block.first, block.second.getClass().getSimpleName()));
					}
					
					libBlock = (HunkLibBlock)bb;
				} break;
				case HUNK_INDEX: {
					if (libBlock == null) {
						throw new HunkParseError("HUNK_INDEX doesn't contain corresponding HUNK_LIB block");
					}
					
					for (HunkIndexUnitEntry unitEntry : ((HunkIndexBlock)bb).getHunkIndexUnitEntries()) {
						int offset = unitEntry.getFirstHunkLongOff() * 4;
						System.out.println(String.format("HunkOffset: 0x%08X, Name: %s", offset, unitEntry.getName()));
						
						HunkBlock block = null;
						
						for (Pair<Integer, HunkBlock> block_ : libBlock.getHunkBlocks()) {
							if (block_.first == firstLibUnitOffset[0] + offset) {
								block = block_.second;
								break;
							}
						}
						
						if (block == null) {
							throw new HunkParseError("Cannot find corresponding index block");
						}
						
						for (HunkIndexHunkEntry hunkEntry : unitEntry.getHunkIndexHunkEntries()) {
							System.out.println(String.format("Entry name: %s, Type: %s, Size: %d", hunkEntry.getName(), HunkType.fromInteger(hunkEntry.getHunkCtype()).name(), hunkEntry.getHunkLongs() * 4));
							
							for (HunkIndexSymbolDef symDef : hunkEntry.getSymDefs()) {
								System.out.println(String.format("Def name: %s, Value: %d, Type: %d", symDef.getName(), symDef.getValue(), symDef.getSymCtype()));
							}
							
							for (HunkIndexSymbolRef symRef : hunkEntry.getSymRefs()) {
								System.out.println(String.format("Ref name: %s, Width: %d", symRef.getName(), symRef.getWidth()));
							}
						}
					}
					
					libBlock = null;
					firstLibUnitOffset[0] = -1;
				} break;
				case HUNK_NAME: {
					lastName = ((HunkNameBlock)bb).getName();
					unitSize += bb.getSize();
				} break;
				case HUNK_END: {
					if ((i + 1 == blocks.size()) || ((i + 1 < blocks.size()) && (blocks.get(i + 1).second.getHunkType() == HunkType.HUNK_UNIT))) { 
						LibHunkItem item = new LibHunkItem();
						
						item.offset = unitOffset;
						item.name = unitName.isEmpty() ? lastName : unitName;
						item.size = unitSize + bb.getSize();
						
						fsih.storeFile(String.format("%04d_%s.o", fsih.getFileCount() + 1, item.name), fsih.getFileCount(), false, item.size, item);
					} else {
						unitSize += bb.getSize();
					}
				} break;
				default: {
					unitSize += bb.getSize();
				} break;
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
			HunkBlockType hbtFirst = HunkBlockFile.peekType(reader);
			HunkBlockFile hbf = new HunkBlockFile(reader, hbtFirst == HunkBlockType.TYPE_LOADSEG);
			
			long unitsCount = hbf.getHunkBlocks().stream().filter(e -> (e.second.getHunkType() == HunkType.HUNK_UNIT)).count();
			return (hbtFirst == HunkBlockType.TYPE_LIB) || (hbtFirst == HunkBlockType.TYPE_UNIT && unitsCount > 1);
		}
	}

	private static class LibHunkItem {
		private String name;
		private long offset;
		private long size;
	}

}
