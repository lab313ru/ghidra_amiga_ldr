package hunk;

import java.io.IOException;

public class HunkParseError extends IOException {
	private static final long serialVersionUID = 4420220309433610756L;

	public HunkParseError(String msg) {
		super(msg);
	}
	
	public HunkParseError(Throwable e) {
		super(e);
	}
}
