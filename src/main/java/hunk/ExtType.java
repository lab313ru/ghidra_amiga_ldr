package hunk;

enum ExtType {
	EXT_SYMB(0),
	EXT_DEF(1),
	EXT_ABS(2),
	EXT_RES(3),
	EXT_ABSREF32(129),
	EXT_ABSCOMMON(130),
	EXT_RELREF16(131),
	EXT_RELREF8(132),
	EXT_DEXT32(133),
	EXT_DEXT16(134),
	EXT_DEXT8(135),
	EXT_RELREF32(136),
	EXT_RELCOMMON(137),
	EXT_ABSREF16(138),
	EXT_ABSREF8(139),
	EXT_RELREF26(229);
	
	private final int value;
	
	static ExtType fromInteger(int value) {
		ExtType[] arr = values();
		
		for (ExtType t : arr) {
			if (t.value == value) {
				return t;
			}
		}
		return null;
	}
	
	ExtType(int value) {
		this.value = value;
	}
	
	public final int getIntValue() {
		return this.value;
	}
}
