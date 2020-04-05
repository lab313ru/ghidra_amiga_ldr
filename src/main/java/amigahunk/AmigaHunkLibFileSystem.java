package amigahunk;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
			
			Iterator<Map.Entry<Integer, HunkBlock>> hunkBlocks = hbf.getHunkBlocks().entrySet().iterator();
			
			String unitName = null, rsrvName = null;
			int unitOffset = 0, rsrvOffset = -1;
			int unitSize = 0;
			
			while (hunkBlocks.hasNext()) {
				Map.Entry<Integer, HunkBlock> block = hunkBlocks.next();
				
				HunkBlock bb = block.getValue();
				HunkType type = bb.getHunkType();
				
				System.out.println(String.format("%d - %s", fsih.getFileCount() + 1, type.name()));
				
				switch (type) {
				case HUNK_UNIT: {
					unitOffset = block.getKey();
					unitSize = bb.getSize();
					unitName = ((HunkUnitBlock)bb).getName();
				} break;
				case HUNK_NAME: {
					if (unitName == null) {
						unitSize = 0;
						unitName = ((HunkNameBlock)bb).getName();
						unitOffset = block.getKey();
					}
					
					unitSize += bb.getSize();
				} break;
				case HUNK_END: {
					LibHunkItem item = new LibHunkItem();
					
					item.offset = (unitName != null) ? unitOffset : rsrvOffset;
					item.name = (unitName != null) ? (!unitName.isEmpty() ? unitName : String.format("%04d", fsih.getFileCount() + 1)) : rsrvName;
					item.size = unitSize + bb.getSize();
					
					fsih.storeFile(item.name, fsih.getFileCount(), false, item.size, item);
					
					unitSize = unitOffset = 0;
					rsrvOffset = -1;
					unitName = null;
				} break;
				default: {
					if (rsrvOffset == -1) {
						rsrvOffset = block.getKey();
						rsrvName = String.format("%04d_%s", fsih.getFileCount() + 1, type.name());
					}

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
			
			long unitsCount = hbf.getHunkBlocks().entrySet().stream().filter(e -> (e.getValue().getHunkType() == HunkType.HUNK_UNIT)).count();
			return (hbtFirst == HunkBlockType.TYPE_UNIT && unitsCount > 1);
		}
	}

	private static class LibHunkItem {
		private String name;
		private long offset;
		private long size;
	}

}
