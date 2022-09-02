import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.Iterator;
import java.util.OptionalLong;

public class ShuMengStrDec extends GhidraScript {

    public static long strdecAddress = 0x29b08;

    // run all function contains strdec function
    public Reference[] getStrRef(){
        Reference[] refs = getReferencesTo(toAddr(strdecAddress));
        return refs;
    }

    public boolean filterAddress(Reference obj){

        if(obj.getReferenceType() == RefType.UNCONDITIONAL_CALL){
            return true;
        }else{
            return false;
        }
    }
    private Long traceVarnodeValue(Varnode argument)  {
        while (!argument.isConstant()) {
            PcodeOp ins = argument.getDef();
            if (ins == null)
                break;
            switch (ins.getOpcode()) {
                case PcodeOp.CAST:
                case PcodeOp.COPY:
                    argument = ins.getInput(0);
                    break;
                case PcodeOp.PTRSUB:
                case PcodeOp.PTRADD:
                    argument = ins.getInput(1);
                    break;
                case PcodeOp.INT_MULT:
                case PcodeOp.MULTIEQUAL:
                    // known cases where an array is indexed
                    return 0l;
                default:
                    return 0l;
            }
        }
        return argument.getOffset();
    }
    public long getFunctionParam(Reference obj) {
        Address target = obj.getFromAddress();
        println(target.toString());
        DecompileOptions options = new DecompileOptions();
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(options);
        ifc.openProgram(currentProgram);
        Function caller = getFunctionContaining(target);
        DecompileResults res = ifc.decompileFunction(caller, 60, monitor);
        HighFunction highFunc = res.getHighFunction();
        LocalSymbolMap lsm = highFunc.getLocalSymbolMap();
        lsm.getSymbols();
        if (highFunc != null) {
//            Iterator<PcodeOpAST> opiter = highFunc.getPcodeOps();
            Iterator<PcodeOpAST> opiter = highFunc.getPcodeOps(target);

            while (opiter.hasNext()) {
                PcodeOpAST op = opiter.next();
                String mnemonic = op.getMnemonic();
                if (mnemonic == "CALL") {
                    Varnode[] inputs = op.getInputs();
                    if(inputs.length <= 1)
                        return 0;
                    Address addr = inputs[0].getAddress();
                    long straddr = traceVarnodeValue(inputs[1]);
                    return straddr;
                }
            }
        }
        return 0l;
    }
    //decrypt string
    public String decryptStr(long encstraddr){
        Memory mem = currentProgram.getMemory();
        try {
            byte[] sx = new byte[100];
            String out = "";
            byte bVar3 = mem.getByte(toAddr(encstraddr + 1));
//            println(String.format("%x", bVar3));
            byte s = bVar3;
            byte[] truedata = null;
            sx[0] = bVar3;
            if(bVar3 != 0){
                int iVar5 = 0;
                int lVar7 = 3;
                byte pbVar8 = s;
                byte pcVar1 = 0;
                do {
                    sx[iVar5] = (byte)(bVar3 - 1 ^ (byte)iVar5);
                    bVar3 = mem.getByte(toAddr(encstraddr + lVar7));
                    iVar5 = (int)lVar7 >> 1;
                    sx[iVar5] = bVar3;
                    pcVar1 = mem.getByte(toAddr(encstraddr + lVar7));
                    lVar7 = lVar7 + 2;
                } while (pcVar1 != 0);
//                println("" + iVar5);
//                println("" + lVar7);
                truedata = new byte[iVar5];
                System.arraycopy(sx, 0, truedata, 0, iVar5);
            }
            println(new String(truedata));
            return new String(truedata);
        }catch (Exception e){

        }
        return "";
    }

    // comment on strdec function
    public void commentOnStrdec(Reference obj, String src){
        Address addr = obj.getFromAddress();
//        setPostComment(addr, src);
        setPreComment(addr, src);

    }

    //emulate strdec function
    public void emulateStrdec(){

    }
    @Override
    protected void run() throws Exception {

        Reference[] allRef = getStrRef();
        println("ref lens is " + allRef.length);
        for(Reference ref: allRef){
            if(filterAddress(ref)) {
                long encstraddr = getFunctionParam(ref);
                if(encstraddr != 0) {
                    String srcStr = decryptStr(encstraddr);
                    commentOnStrdec(ref, srcStr);
                }
            }

        }
    }
}
