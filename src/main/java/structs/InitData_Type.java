package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.DuplicateNameException;

public class InitData_Type implements StructConverter {
	
	private Structure s;
	
	public static final int DATA_BYTE_B = 0xA000;
	public static final int DATA_BYTE_W = 0xE000;
	
	public static final int DATA_WORD_B = 0x9000;
	public static final int DATA_WORD_W = 0xD000;
	
	public static final int DATA_LONG_B = 0x8000;
	public static final int DATA_LONG_W = 0xC000;
	
	public static final int DATA_STRUCT_B = 0x8000;
	public static final int DATA_STRUCT_W = 0xC000;
	
	public InitData_Type(Memory mem, FlatProgramAPI fpa, long index) throws Exception {
		int tag = mem.getShort(fpa.toAddr(index));
		int tagMasked = tag & 0xFF00;
		
		s = null;
		
		switch (tagMasked) {
		case DATA_BYTE_B:
		{
			s = new StructureDataType("id_BYTE", 0);
			
			s.add(BYTE, "tag", null);
			s.add(BYTE, "offset", null);
			s.add(BYTE, "value", null);
			s.add(BYTE, "align", null);
		} break;
		case DATA_BYTE_W:
		{
			s = new StructureDataType("id_BYTE", 0);
			
			s.add(WORD, "tag", null);
			s.add(WORD, "offset", null);
			s.add(BYTE, "value", null);
			s.add(BYTE, "align", null);
		} break;
		case DATA_WORD_B:
		{
			s = new StructureDataType("id_WORD", 0);
			
			s.add(BYTE, "tag", null);
			s.add(BYTE, "offset", null);
			s.add(WORD, "value", null);
		} break;
		case DATA_WORD_W:
		{
			s = new StructureDataType("id_WORD", 0);
			
			s.add(WORD, "tag", null);
			s.add(WORD, "offset", null);
			s.add(WORD, "value", null);
		} break;
		case DATA_LONG_B:
		{
			s = new StructureDataType("id_LONG", 0);
			
			s.add(BYTE, "tag", null);
			s.add(BYTE, "offset", null);
			s.add(DWORD, "value", null);
		} break;
		case DATA_LONG_W:
		{
			s = new StructureDataType("id_LONG", 0);
			
			s.add(WORD, "tag", null);
			s.add(WORD, "offset", null);
			s.add(DWORD, "value", null);
		} break;
		default:
		{
			if ((tagMasked & DATA_STRUCT_B) == DATA_STRUCT_B) {
				s = new StructureDataType("id_STRUCT", 0);
				
				s.add(BYTE, "TagSizeCount", "0x80 | (size << 4) | count");
				s.add(BYTE, "offset", null);
			} else if ((tagMasked & DATA_STRUCT_W) == DATA_STRUCT_W) {
				s = new StructureDataType("id_STRUCT", 0);
				
				s.add(BYTE, "TagSizeCount", "0xC0 | (size << 4) | count");
				s.add(BYTE, 3, "offset", null);
			} else {
				throw new Exception("Wrong data type!");
			}
		}
		}
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}

}
