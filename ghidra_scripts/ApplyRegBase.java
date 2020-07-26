//This script applies selected register value to the whole program.
//@author Dr. MefistO
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramContext;

public class ApplyRegBase extends GhidraScript {

	private static final String REG = "A4";
	
	@Override
	protected void run() throws Exception {
		Listing l = this.currentProgram.getListing();
		
		Register reg = this.currentProgram.getRegister(REG);
		Address addr = this.askAddress(String.format("%s register base", REG), String.format("Specify %s register base address:", REG));
		
		FunctionIterator fi = l.getFunctions(true);
		
        while (fi.hasNext() && !monitor.isCancelled())
        {
            doAnalysis(fi.next(), reg, addr);
        }
        
        analyzeAll(currentProgram);
	}
	
	private void doAnalysis(Function func, Register reg, Address addr) {
		if (func == null) {
    		println("No function to analyze.");
    		return;
    	}

		try {
			monitor.setMessage(String.format("Analyzing %s reg usage in %s", REG, func.getName()));
			
			ProgramContext ctx = this.getCurrentProgram().getProgramContext();
			if (ctx.getRegisterValue(reg, addr) != null) {
	        	return;
	        }
			
			ctx.setRegisterValue(func.getBody().getMinAddress(), func.getBody().getMaxAddress(), new RegisterValue(reg, addr.getOffsetAsBigInteger()));
		} catch (ContextChangeException e1) {
			return;
		}
	}
}
