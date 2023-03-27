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

VOID RecordMemRead(VOID * ip, VOID * addr, UINT32 size)
{
    log("[Real Execution] [MEMREAD] %p, memaddr: %p, size: %d\n", ip, addr, size);
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
	    switch(offset){
			// case 0xae4e:
			//    {
			//    	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EveryInst, 
	  //           	IARG_INST_PTR, 
   //                  IARG_REG_REFERENCE, REG_RAX, 
   //                  IARG_REG_REFERENCE, REG_RBX, 
   //                  IARG_REG_REFERENCE, REG_RCX, 
   //                  IARG_REG_REFERENCE, REG_RDX,
   //                  IARG_END);
			//    }
			// break;
			case 0xae44:
				ADDRINT target = addr - 0x44 + 0x70;
				INS_InsertDirectJump(ins, IPOINT_BEFORE, target);
			break;
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
