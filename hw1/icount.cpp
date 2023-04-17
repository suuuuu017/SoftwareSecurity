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

VOID EveryInst(ADDRINT ip,
               ADDRINT * regRAX,
               ADDRINT * regRBX,
               ADDRINT * regRCX,
               ADDRINT * regRDX)
{
    log("[Real Execution] EAX: [%lx]\n", *regRAX); // read value
    *regRAX = 0; // new value
}

VOID RecordMemWriteAfter(VOID * ip, VOID * addr, UINT32 size)
{
    unsigned char* p = (unsigned char*)addr;
    for( unsigned  int i = 0; i < size; i++ ) {
	    *p = 0;
        p++;
    }
}

VOID RecordMemWriteAfter_Profile(VOID * ip, VOID * addr, UINT32 size, ADDRINT * regRSP)
{
    ADDRINT offset = ADDRINT(ip) - g_addrLow;

    log("[MEMWRITE(AFTER)] %p (hitcount: %d), mem : %p (sz: %d) (stack: %p) ->",
            offset, g_accessMap[offset], addr, size, *regRSP);
    LogData(addr, size);
}

VOID RecordMemWriteAfter_Naive(VOID * ip, VOID * addr, UINT32 size, ADDRINT * regRSP)
{
    ADDRINT offset = ADDRINT(ip) - g_addrLow;

    if (0x7fffffffdf8c == ADDRINT(addr)){
        log("[MEMWRITE] collision %p, mem: %p (sz: %d) ->",
                offset, addr, size);
        LogData(addr, size);
        memset(addr, 0, size);
    }
    if (0x7fffffffdf54 == ADDRINT(addr)){
        log("[MEMWRITE] isOver %p, mem: %p (sz: %d) ->",
            offset, addr, size);
        LogData(addr, size);
        memset(addr, 0, size);
    }
}

VOID RecordMemRead(VOID * ip, VOID * addr, UINT32 size)
{
    // log("[Real Execution] [MEMREAD] %p, memaddr: %p, size: %d\n", ip, addr, size);
    unsigned char* p = (unsigned char*)addr;
    for( unsigned  int i = 0; i < size; i++ ) {
        log("%02x ", (unsigned char)*p);
        p++;
    }
    log("\n");
}

VOID Instruction(INS ins, VOID* v) {
    string strInst = INS_Disassemble(ins);
    ADDRINT addr = INS_Address(ins);
    
    if(g_bMainExecLoaded){
        if (g_addrLow <= addr && addr < g_addrHigh){
            // minus g_addrLow to offset the addr to the same even ASLR is not disabled
                //log("[Read/Parse/Translate] [%lx] %s\n", addr - g_addrLow, strInst.c_str());
            ADDRINT offset = addr - g_addrLow;
            if (offset == 0x1c65 || offset == 0x1d9a){
                UINT32 memOperands = INS_MemoryOperandCount(ins);
                for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
                    if (INS_OperandIsImplicit(ins, memOp)) {
                        continue;
                    }
//                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
//                        INS_InsertCall(
//                                ins, IPOINT_AFTER, (AFUNPTR) RecordMemWriteAfter_Naive,
//                                IARG_INST_PTR,
//                                IARG_MEMORYOP_EA, memOp,
//                                IARG_MEMORYWRITE_SIZE,
//                                IARG_REG_REFERENCE, REG_RSP,
//                                IARG_END);
//
//                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        INS_InsertCall(
                                ins, IPOINT_AFTER, (AFUNPTR) RecordMemWriteAfter_Profile,
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

VOID Fini(INT32 code, VOID* v) { cerr << "Count " << ins_count << endl; }

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
