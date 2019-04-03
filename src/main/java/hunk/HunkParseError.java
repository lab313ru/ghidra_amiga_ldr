package hunk;

import java.io.IOException;

class HunkParseError extends IOException {
	public HunkParseError(String msg) {
		super(msg);
	}
	
	public HunkParseError(Throwable e) {
		super(e);
	}
}
