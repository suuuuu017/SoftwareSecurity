/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  This file contains an ISA-portable PIN tool for counting dynamic instructions
 */

#include "pin.H"
#include <iostream>
using std::cerr;
using std::endl;

using namespace std;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

UINT64 ins_count = 0;

ADDRINT g_addrLow, g_addrHigh;
BOOL g_bMainExecLoaded = FALSE;
FILE* g_fpLog = 0;
unsigned short g_accessMap[0xFFFF];

#define DBG_LOG g_fpLog

void log_init(){
	g_fpLog = fopen("log.txt", "wt");
}

void log(const char * format, ...){
	if(g_fpLog == 0) log_init();

	va_list args;
	va_start(args, format);
	vfprintf(g_fpLog, format, args);
	va_end(args);
}

VOID ImageLoad(IMG img, VOID *v)
{
    if( IMG_IsMainExecutable(img) ) {
        g_addrLow = IMG_LowAddress(img);
        g_addrHigh = IMG_HighAddress(img);

        // Use the above addresses to prune out non-interesting instructions.
        g_bMainExecLoaded = TRUE;

	fprintf(DBG_LOG, "[IMG] Main Exec.: %lx ~ %lx\n", IMG_LowAddress(img), IMG_HighAddress(img));
    }
    else{
	fprintf(DBG_LOG, "[ING] Library   : %lx ~ %lx\n", IMG_LowAddress(img), IMG_HighAddress(img));
    }
}

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamic instructions executed to stderr.\n"
            "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */

VOID docount() { ins_count++; }

/* ===================================================================== */

int IsStackMem_Heuristic(ADDRINT rsp, ADDRINT mem)
{
    if( (rsp - 0x10000) < mem && mem < (rsp + 0x10000) ) {
        return 1;
    }
    return 0;
}

void LogData(VOID* addr, UINT32 size)
{
    switch( size ) {
        case 4:
        {
            unsigned int* pData = (unsigned int*)addr;
            log("%ld\n", *pData);
        }
            break;
        case 8:
        {
            unsigned long int* pData = (unsigned long int*)addr;
            log("%lld\n", *pData);
        }
            break;
        default:
        {
            unsigned char* pData = (unsigned char*)addr;
            for( unsigned  int i = 0; i < size; i++, pData++ ) {
                log("%02x ", (unsigned char)*pData);
            }
            log("\n");
        }
            break;
    }
}

VOID RecordMemWriteAfter(VOID * ip, VOID * addr, UINT32 size, ADDRINT* regRSP)
{
    ADDRINT offset = (ADDRINT)ip - g_addrLow;

    if (IsStackMem_Heuristic(*regRSP, (ADDRINT)addr)){
        return;
    }
    g_accessMap[offset]++;
    log("[MEMWRITE(AFTER)] %p (hitcount: %d), mem: %p (sz: %d) (stack: %p) ->",
            offset, g_accessMap[offset], addr, size, *regRSP);
    LogData(addr, size);
}


VOID Instruction(INS ins, VOID* v) {
    string strInst = INS_Disassemble(ins);
    ADDRINT addr = INS_Address(ins);
    
    if(g_bMainExecLoaded){
        if (g_addrLow <= addr && addr < g_addrHigh){
            ADDRINT offset = addr - g_addrLow;
            log("[Read/Parse/Translate] [%lx] %s\n", offset, strInst.c_str());
            const char* pszInst = strInst.c_str();
            if (strstr(pszInst, "push r") == pszInst){
                return;
            }

            if (INS_IsValidForIpointAfter(ins) == TRUE && INS_IsCall(ins) == FALSE && INS_IsMemoryWrite(ins) == TRUE){
                UINT32 memOperands = INS_MemoryOperandCount(ins);
                for (UINT32 memOp = 0; memOp < memOperands; memOp++){
                    if(INS_OperandIsImplicit(ins, memOp)){
                        continue;
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)){
                    INS_InsertCall(
                                    ins, IPOINT_AFTER, (AFUNPTR)RecordMemWriteAfter,
                                    IARG_INST_PTR,
                                    IARG_MEMORYOP_EA, memOp,
                                    IARG_MEMORYWRITE_SIZE,
                                    IARG_REG_REFERENCE, REG_RSP,
                                    IARG_END);

                    }
                }
            }
        }
    }
}
/* ===================================================================== */

VOID Fini(INT32 code, VOID* v) {
    for(int i = 0; i < 0xFFFF; i++){
        if(g_accessMap[i]){
            log("offset: %x, max-hitcount %d\n", i, g_accessMap[i]);
        }
    }
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    DBG_LOG = fopen("log.txt", "wt");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Never returns
    PIN_StartProgram();

    // nothing here will be executed

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
