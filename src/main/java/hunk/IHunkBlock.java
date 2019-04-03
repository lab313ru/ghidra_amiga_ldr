package hunk;

import ghidra.app.util.bin.BinaryReader;

interface IHunkBlock {
	// public void setup(String[] hunkSizes) throws HunkParseError;
    void parse(BinaryReader reader) throws HunkParseError;
}
