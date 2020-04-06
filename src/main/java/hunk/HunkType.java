package hunk;

public enum HunkType {
	HUNK_BAD_TYPE(0xDEADBEEF),
	
	HUNK_UNIT(999),
	HUNK_NAME(1000),
	HUNK_CODE(1001),
	HUNK_DATA(1002),
	HUNK_BSS(1003),
	HUNK_ABSRELOC32(1004),
	HUNK_RELRELOC16(1005),
	HUNK_RELRELOC8(1006),
	HUNK_EXT(1007),
	HUNK_SYMBOL(1008),
	HUNK_DEBUG(1009),
	HUNK_END(1010),
	HUNK_HEADER(1011),

	HUNK_OVERLAY(1013),
	HUNK_BREAK(1014),
	HUNK_DREL32(1015),
	HUNK_DREL16(1016),
	HUNK_DREL8(1017),
	HUNK_LIB(1018),
	HUNK_INDEX(1019),
	HUNK_RELOC32SHORT(1020),
	HUNK_RELRELOC32(1021),
	HUNK_ABSRELOC16(1022),

	HUNK_PPC_CODE(1257),
	HUNK_RELRELOC26(1260);
	
	private final int value;
	
	public static final int HUNK_TYPE_MASK = 0xFFFF;
	
	public static HunkType fromInteger(int value) {
		HunkType[] arr = values();
		
		for (HunkType t : arr) {
			if (t.value == value) {
				return t;
			}
		}
		return null;
	}
	
	HunkType(int value) {
		this.value = value;
	}
	
	public final int getValue() {
		return this.value;
	}
	
	@Override
	public final String toString() {
		return this.name();
	}
}
