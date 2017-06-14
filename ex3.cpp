#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include <map>
#include <list>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <values.h>

#define PROFILE_NAME "__profile.map"
#define MAX_FINE_NAME_SIZE 30
#define NUMBER_TC_RTNS 10

#define debug(x) (cerr << x << endl )

/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobProfile(KNOB_MODE_WRITEONCE,    "pintool",
    "prof", "0", "Profiling run");

KNOB<BOOL>   KnobGenerateBinary(KNOB_MODE_WRITEONCE,    "pintool",
    "inst", "0", "Profiling run");

KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE,    "pintool",
    "verbose", "0", "Verbose run");

KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "no_tc_commit", "0", "Do not commit translated code");





/* ======================================= */
// Types and structures
/* ======================================= */
typedef struct _instr_table_t {
    UINT64 count;
} instr_table_t;


using namespace std;

//================ BBL class ===================

class BBL_Class {
public:
	ADDRINT start;
    ADDRINT finish;
    UINT id;
	
	BBL_Class():
        start(0), finish(0), id(0){
	}

	BBL_Class(ADDRINT _src, ADDRINT _dst, UINT _id):
        start(_src), finish(_dst), id(_id){
    }

	BBL_Class(ADDRINT _src, ADDRINT _dst):
        start(_src), finish(_dst), id(0){
    }

    void setId(UINT _id){
        id = _id;
    }

	UINT getId() const{
		return this->id;
	}

	ADDRINT getStart() const{
		return this->start;
	}

	ADDRINT getFinish() const{
		return this->finish;
	}

	bool operator<(const BBL_Class& rhs) const
	{
		return this->start < rhs.getStart();
	}


private:

};
//============================================

//================ Edge class ===================
class Edge_Class{

public:
	ADDRINT src;
	ADDRINT dst;
	UINT src_id;
	UINT dst_id;
	UINT64 edge_count;
	UINT id;
	static int cnt;
	
	Edge_Class(ADDRINT _src, ADDRINT _dst) {
		src = _src;
		src_id = 0;
		dst_id = 0;
		dst = _dst;
		edge_count = 0;
		cnt++;
	}

	ADDRINT getSrc() {
		return this->src;
	}

	ADDRINT getDst() {
		return this->dst;
	}
	
	void incrementCount() {
		this->edge_count++;
	}

	void setId(UINT _id) {
		this->id = _id;
	}

	UINT getId() const {
		return this->id;
	}

	UINT64 getCount() {
		return this->edge_count;
	}

	bool operator<(const Edge_Class& rhs) const
	{
		if (this->edge_count == rhs.edge_count) {
			return this->src > rhs.src;
		}

		return this->edge_count < rhs.edge_count;
	}

private:

};
int Edge_Class::cnt = 0;


//============================================

//================ RTN class ===================
class RTN_Class 
{
public:
	std::list <BBL_Class*> bbllist;
	std::list <Edge_Class*> edgelist;
	string name;
	ADDRINT addr;
	UINT64 icount;

	RTN_Class(string _name, ADDRINT _addr) { //C'tor
		name = _name;
		addr = _addr;
		icount = 0;
	}


	BBL_Class* addBbl(ADDRINT start, ADDRINT finish) {
		
		BBL_Class* bbl = new BBL_Class(start, finish);
		std::list<BBL_Class*>::iterator it = bbllist.begin();
		for (std::list<BBL_Class*>::iterator it = bbllist.begin(); it != bbllist.end(); it++) {
			
			if ((*it)->getStart() == bbl->getStart() && (*it)->getFinish() == bbl->getFinish()) {
				
				return (*it); //BBL aready in the list
			}
		}

			
		
		bbllist.push_back(bbl);
		return bbl;
}

	Edge_Class* addEdge(ADDRINT curr_addr, ADDRINT target_addr) {
		
		std::list<Edge_Class*>::iterator it;
		for (it = edgelist.begin(); it != edgelist.end(); it++) {
			if ((*it)->getSrc() == curr_addr && (*it)->getDst() == target_addr) {
				return (*it); 
			}
		}
		Edge_Class* edge = new Edge_Class(curr_addr, target_addr);
		
		edgelist.push_back(edge);
		return edge;
	}

	
	
	
	void assignBblId() {
		std::list<BBL_Class*>::iterator it;
    	int i;
		for (it = bbllist.begin(), i=1; it != bbllist.end(); it++, i++) {
			(*it)->setId(i);
			}
	}

	void assignEdgeId() {
		std::list<Edge_Class*>::iterator it;
    	int i;
		for (it = edgelist.begin(), i=1; it != edgelist.end(); it++, i++) {
			(*it)->setId(i);
		}
		return;
	}
	
	
	void setBBltoEdge(){
		std::list<Edge_Class*>::iterator it_edge;
		for (it_edge = edgelist.begin(); it_edge != edgelist.end(); it_edge++) {
			std::list<BBL_Class*>::iterator it_bbl;
			for (it_bbl = bbllist.begin(); it_bbl != bbllist.end(); it_bbl++) {
				if((*it_bbl)->start == (*it_edge )->dst) (*it_edge )->src_id = (*it_bbl)->id;
				if((*it_bbl)->finish == (*it_edge )->src) (*it_edge )->dst_id = (*it_bbl)->id;
			}			
			
		}
	}
	
	
	

	bool operator<(const RTN_Class& rhs) const
	{
		return this->icount < rhs.getIcount();
	}

	
	string getName() {
		return this->name;
	}

	ADDRINT getAddr() {
		return this->addr;
	}

	UINT64* getIcountPtr(){
		return &(this->icount);
	}

	UINT64 getIcount() const{
		return icount;
	}
	
private:

};

//============================================


/* ======================================= */
// Global variables
/* ======================================= */

//for ex2
ofstream outFile;

instr_table_t *instrTable = NULL; 
list<RTN_Class*> rtn_list;
USIZE instrCountTableSize = 0;

//for ex3
list<ADDRINT> top10_rtn_addr; //out

std::ofstream* out = 0;

// For XED:
#if defined(TARGET_IA32E)
    xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES  14

// tc containing the new code:
char *tc;	
int tc_cursor = 0;

// instruction map with an entry for each new instruction:
typedef struct { 
	ADDRINT orig_ins_addr;
	ADDRINT new_ins_addr;
	ADDRINT orig_targ_addr;
	bool hasNewTargAddr;
	char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
	xed_category_enum_t category_enum;
	unsigned int size;
	int new_targ_entry;
} instr_map_t;


instr_map_t *instr_map = NULL;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;


// total number of routines in the main executable module:
int max_rtn_count = 0;

// Tables of all candidate routines to be translated:
typedef struct { 
	ADDRINT rtn_addr; 
	USIZE rtn_size;
	int instr_map_entry;   // negative instr_map_entry means routine does not have a translation.
	bool isSafeForReplacedProbe;	
} translated_rtn_t;

translated_rtn_t *translated_rtn;
int translated_rtn_num = 0;


/* ======================================= */
// Helper functions
/* ======================================= */


bool compareRtn(const RTN_Class* lhs, const RTN_Class* rhs)
{
	return (*lhs) < (*rhs);
}

bool compareBbl(const BBL_Class* lhs, const BBL_Class* rhs)
{
	return (*lhs).start > (*rhs).start;
}

bool compareEdge(const Edge_Class* lhs, const Edge_Class* rhs)
{
	return (*lhs) < (*rhs);
}


bool isTopTenRTN(RTN rtn){
    ADDRINT rtnAdd = RTN_Address(rtn);
    std::list<ADDRINT>::iterator itr = std::find(top10_rtn_addr.begin(), top10_rtn_addr.end(), rtnAdd);
    if(itr == top10_rtn_addr.end()) return false;
    return true;
}


/* ======================================= */
// Utilities
/* ======================================= */

/** This function is called before every instruction is executed
*	@recieves: counter - ptr to icount of RTN
*			   inc - number of instructions in the current BBL
*
**/
VOID docount(UINT64* counter, UINT32 inc)
{
	*counter += inc;
}

VOID docount2(UINT64* branchCounter, UINT64* fallthroughCounter, BOOL taken)
{
    taken ? (*branchCounter)++ : (*fallthroughCounter)++;
}







VOID InitProfile()
{

    int fd;
    char profileFilename[MAX_FINE_NAME_SIZE];

    // profile map should have 1 64-bit integer for each of the counters we save
    instrCountTableSize = (rtn_list.size())*3 + Edge_Class::cnt +1; //For RTNs we save address and count AND number of RTNs
	//cerr << (void*)instrCountTableSize << endl;

    //open the profile file:
    strcpy(profileFilename, "__profile.map");

    //check if pofile file exists:
    bool isProfileFile = false;
    if( access(profileFilename, F_OK ) != -1 ) {
        isProfileFile = true;// file exists
    }

    // open the profile file and map it to memory:
    fd = open(profileFilename, O_CREAT | O_RDWR, S_IRWXU);
    if (fd == -1) {
        cerr << "open " << endl;
        exit(1);
    }
	
	//write(fd,(void*)instrCountTableSize,sizeof(instrCountTableSize));

    /* go to the location corresponding to the last byte */
    if (lseek (fd, (instrCountTableSize * sizeof(instr_table_t)) - 1, SEEK_SET) == -1) {
        cerr << "lseek error" << endl;
        exit(1);
    }

    /* write a dummy byte at the last location */
    if (write (fd, "", 1) != 1) {
        cerr << "write error " << endl;
        exit(1);
    }

    instrTable = (instr_table_t *)mmap(0, instrCountTableSize * sizeof(instr_table_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE , fd, 0);
    if ((ADDRINT) instrTable == 0xffffffffffffffff) {
        cerr << "mmap" << endl;
        exit(1);
    }

    if (!isProfileFile)
        memset(instrTable, 0, instrCountTableSize * sizeof(instr_table_t));
}





/* ======================================= */
// Instumentation callbacks
/* ======================================= */


void TRACEINFO(TRACE trc, void* v)
{
	//int cnt_trans = 0;

	for(BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		//cnt_trans++;
		//curr BBL
		
		ADDRINT start_add = INS_Address(BBL_InsHead(bbl));
		ADDRINT end_add = INS_Address(BBL_InsTail(bbl));	
		ADDRINT curr_addr = BBL_Address(bbl);
		INS bbl_tail = BBL_InsTail(bbl);
		RTN rtn = RTN_FindByAddress(BBL_Address(bbl)); // get current RTN
		
		if(!RTN_Valid(rtn)) return;
		
		RTN_Class* curr_rtn= 0;
		bool if_taken_flag = false;
		ADDRINT rtn_addr = RTN_Address(rtn);
		string rtn_name = RTN_Name(rtn);

		std::list<RTN_Class*>::iterator it;
		for (it = rtn_list.begin(); it != rtn_list.end(); it++) {
			//cerr << (*it)->addr << "          " << rtn_addr << endl;
			if ((*it)->addr == rtn_addr) { //RTN already exists
				//cerr << "It does work" << endl;
				if_taken_flag = true;
				curr_rtn = (*it);
				break;
			}
		}
		
		//Create a new RTN_Class and inserts to the list
		if(if_taken_flag==false){
			RTN_Class* newrtn = new RTN_Class(rtn_name, rtn_addr);
			rtn_list.push_front(newrtn);
			curr_rtn = newrtn;		
		}
		

		// Insert a call to docount before every bbl, passing the number of instructions
		BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, curr_rtn->getIcountPtr(), IARG_UINT32, BBL_NumIns(bbl), IARG_END);
		
		curr_rtn -> addBbl(start_add, end_add);

		       
		ADDRINT next_addr = INS_NextAddress( bbl_tail); 
		Edge_Class* edgenext = curr_rtn ->addEdge(curr_addr, next_addr);
		

       if(INS_IsDirectBranchOrCall(bbl_tail))
        {
			ADDRINT target_addr = INS_DirectBranchOrCallTargetAddress(bbl_tail); 
			Edge_Class* edgebranch = curr_rtn ->addEdge(curr_addr, target_addr);
			INS_InsertCall(bbl_tail, IPOINT_BEFORE, (AFUNPTR)docount2, IARG_PTR,&(edgebranch->edge_count), IARG_PTR,&( edgenext->edge_count), IARG_BRANCH_TAKEN, IARG_END);
		}
		else if(INS_IsIndirectBranchOrCall(bbl_tail))
        {
		
            INS_InsertCall(bbl_tail, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(edgenext->edge_count),  IARG_UINT32, 1, IARG_END);
        }
		

	}
}



// This function is called when the application exits
// It prints the id and count for each procedure
VOID Fini(INT32 code, VOID *v)
{
	
	outFile.open("rtn-output.txt"); 
	rtn_list.sort(compareRtn);
	rtn_list.reverse();
	
	 // allocate __profile.map
	InitProfile();

	int j = 0;
	instrTable[j++].count = instrCountTableSize;
	for (list<RTN_Class*>::iterator rtn_it = rtn_list.begin(); rtn_it != rtn_list.end(); rtn_it++) {

		UINT64 count = instrTable[j++].count += *((*rtn_it)->getIcountPtr()) ;
		instrTable[j++].count = (*rtn_it)->getAddr();
		//print RTN
		outFile << (*rtn_it)->getName() << ": " << StringHex((*rtn_it)->getAddr(), 1) \
			<< " icount: " << count << endl;

		//sort BBLs of current RTN
		(*rtn_it)->bbllist.sort(compareBbl);
		(*rtn_it)->bbllist.reverse();

		(*rtn_it)->assignBblId();


		//sort Edges of current RTN
		(*rtn_it)->edgelist.sort(compareEdge);
		(*rtn_it)->edgelist.reverse();
	//	(*rtn_it)->setBBltoEdge();
		(*rtn_it)->assignEdgeId();


		//print BBLs
		std::list<BBL_Class*>::iterator bbl_it;

		for(bbl_it = (*rtn_it)->bbllist.begin(); bbl_it != (*rtn_it)->bbllist.end(); bbl_it++)  {

			outFile << "\tBB" << (*bbl_it)->getId() << ": " << StringHex((*bbl_it)->getStart(), 1) \
			<< " - " << StringHex((*bbl_it)->getFinish(), 1) << endl;
			
			for (std::list<Edge_Class*>::iterator edge_it = (*rtn_it)->edgelist.begin(); edge_it != (*rtn_it)->edgelist.end(); edge_it++) {
				if((*edge_it)->src == (*bbl_it)->getStart())
					(*edge_it)->src_id = (*bbl_it)->getId();
				if((*edge_it)->dst == (*bbl_it)->getStart())
					(*edge_it)->dst_id = (*bbl_it)->getId();
			}
		}


		//print Edges
		std::list<Edge_Class*>::iterator edge_it;
		instrTable[j++].count = (*rtn_it)->edgelist.size(); //size of the current BBL list
		
		for (edge_it = (*rtn_it)->edgelist.begin(); edge_it != (*rtn_it)->edgelist.end(); edge_it++) {
			UINT64 count = instrTable[j++].count += (*edge_it)->getCount() ;
			
			if(count> 0){
			outFile << "\t\tEdge" << (*edge_it)->getId() << ": " << "BB" << (*edge_it)->src_id \
				<< " --> " << "BB" << (*edge_it)->dst_id<< "\t" << count << endl;
			}

		}
		//	 cerr << "!!!!!!!!!!!!!!!!!!!!!!!" << endl;
	}
  
 		outFile.close(); // close "rtn-output.txt"
    
}



/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

/*************************/
/* dump_all_image_instrs */
/*************************/
void dump_all_image_instrs(IMG img)
{
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			// Open the RTN.
            RTN_Open( rtn );

			cerr << RTN_Name(rtn) << ":" << endl;

			for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
            {				
	              cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
			}

			// Close the RTN.
            RTN_Close( rtn );
		}
	}
}


/*************************/
/* dump_instr_from_xedd */
/*************************/
void dump_instr_from_xedd (xed_decoded_inst_t* xedd, ADDRINT address)
{
	// debug print decoded instr:
	char disasm_buf[2048];

    xed_uint64_t runtime_address = reinterpret_cast<xed_uint64_t>(address);  // set the runtime adddress for disassembly 

   xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), runtime_address, 0, 0);

    cerr << hex << address << ": " << disasm_buf <<  endl;
}


/************************/
/* dump_instr_from_mem */
/************************/
void dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;

  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
  if (!xed_ok){
	  cerr << "invalid opcode" << endl;
	  return;
  }
 
  //xed_decoded_inst_dump_intel_format(&new_xedd, disasm_buf, 2048, new_addr);
   xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, sizeof(disasm_buf), new_addr, 0, 0);

  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;  
 
}


/****************************/
/*  dump_entire_instr_map() */
/****************************/
void dump_entire_instr_map()
{	
	for (int i=0; i < num_of_instr_map_entries; i++) {
		for (int j=0; j < translated_rtn_num; j++) {
			if (translated_rtn[j].instr_map_entry == i) {

				RTN rtn = RTN_FindByAddress(translated_rtn[j].rtn_addr);

				if (rtn == RTN_Invalid()) {
					cerr << "Unknwon"  << ":" << endl;
				} else {
				  cerr << RTN_Name(rtn) << ":" << endl;
				}
			}
		}
		dump_instr_from_mem ((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);		
	}
}


/**************************/
/* dump_instr_map_entry */
/**************************/
void dump_instr_map_entry(int instr_map_entry)
{
	cerr << dec << instr_map_entry << ": ";
	cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
	cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
	cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

	ADDRINT new_targ_addr;
	if (instr_map[instr_map_entry].new_targ_entry >= 0)
		new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;
	else
		new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;

	cerr << " new_targ_addr: " << hex << new_targ_addr;
	cerr << "    new instr:";
	dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}


/*************/
/* dump_tc() */
/*************/
void dump_tc()
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;
  ADDRINT address = (ADDRINT)&tc[0];
  unsigned int size = 0;

  while (address < (ADDRINT)&tc[tc_cursor]) {

      address += size;

	  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
	  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

	  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	  if (!xed_ok){
		  cerr << "invalid opcode" << endl;
		  return;
	  }
 
	 // xed_decoded_inst_dump_intel_format(&new_xedd, disasm_buf, 2048, address);
      xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, sizeof(disasm_buf), address, 0, 0);

	  cerr << "0x" << hex << address << ": " << disasm_buf <<  endl;

	  size = xed_decoded_inst_get_length (&new_xedd);	
  }
}


/* ============================================================= */
/* Translation routines                                         */
/* ============================================================= */


/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size)
{

	// copy orig instr to instr map:
    ADDRINT orig_targ_addr = 0;

	if (xed_decoded_inst_get_length (xedd) != size) {
		cerr << "Invalid instruction decoding" << endl;
		return -1;
	}

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);
	
	xed_int32_t disp;

    if (disp_byts > 0) { // there is a branch offset.
      disp = xed_decoded_inst_get_branch_displacement(xedd);
	  orig_targ_addr = pc + xed_decoded_inst_get_length (xedd) + disp;	
	}

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;
	
	xed_error_enum_t xed_error = xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;		
		return -1;
	}	
	
	// add a new entry in the instr_map:
	
	instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
	instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
	instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr; 
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
	instr_map[num_of_instr_map_entries].new_targ_entry = -1;
	instr_map[num_of_instr_map_entries].size = new_size;	
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);

	num_of_instr_map_entries++;

	// update expected size of tc:
	tc_cursor += new_size;    	     

	if (num_of_instr_map_entries >= max_ins_count) {
		cerr << "out of memory for map_instr" << endl;
		return -1;
	}
	

    // debug print new encoded instr:
	if (KnobVerbose) {
		cerr << "    new instr:";
		dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins, instr_map[num_of_instr_map_entries-1].new_ins_addr);
	}

	return new_size;
}


/*************************************************/
/* chain_all_direct_br_and_call_target_entries() */
/*************************************************/
int chain_all_direct_br_and_call_target_entries()
{
	for (int i=0; i < num_of_instr_map_entries; i++) {			    

		if (instr_map[i].orig_targ_addr == 0)
			continue;

		if (instr_map[i].hasNewTargAddr)
			continue;

        for (int j = 0; j < num_of_instr_map_entries; j++) {

            if (j == i)
			   continue;
	
            if (instr_map[j].orig_ins_addr == instr_map[i].orig_targ_addr) {
                instr_map[i].hasNewTargAddr = true; 
	            instr_map[i].new_targ_entry = j;
                break;
			}
		}
	}
   
	return 0;
}


/**************************/
/* fix_rip_displacement() */
/**************************/
int fix_rip_displacement(int instr_map_entry) 
{
	//debug print:
	//dump_instr_map_entry(instr_map_entry);

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

	if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
		return 0;

	//cerr << "Memory Operands" << endl;
	bool isRipBase = false;
	xed_reg_enum_t base_reg = XED_REG_INVALID;
	xed_int64_t disp = 0;
	for(unsigned int i=0; i < memops ; i++)   {

		base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
		disp = xed_decoded_inst_get_memory_displacement(&xedd,i);

		if (base_reg == XED_REG_RIP) {
			isRipBase = true;
			break;
		}
		
	}

	if (!isRipBase)
		return 0;

			
	//xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
	xed_int64_t new_disp = 0;
	xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

	unsigned int orig_size = xed_decoded_inst_get_length (&xedd);

	// modify rip displacement. use direct addressing mode:	
	new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size; // xed_decoded_inst_get_length (&xedd_orig);
	xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

	//Set the memory displacement using a bit length 
	xed_encoder_request_set_memory_displacement (&xedd, new_disp, new_disp_byts);

	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;
			
	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);
	
	xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry); 
		return -1;
	}				

	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}

	return new_size;
}


/************************************/
/* fix_direct_br_call_to_orig_addr */
/************************************/
int fix_direct_br_call_to_orig_addr(int instr_map_entry)
{

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}
	
	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
	
	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {

		cerr << "ERROR: Invalid direct jump from translated code to original code in rotuine: " 
			  << RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}

	// check for cases of direct jumps/calls back to the orginal target address:
	if (instr_map[instr_map_entry].new_targ_entry >= 0) {
		cerr << "ERROR: Invalid jump or call instruction" << endl;
		return -1;
	}

	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	unsigned int olen = 0;
				

	xed_encoder_instruction_t  enc_instr;

	ADDRINT new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
		               instr_map[instr_map_entry].new_ins_addr - 
					   xed_decoded_inst_get_length (&xedd);

	if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_CALL_NEAR, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

	if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


	xed_encoder_request_t enc_req;

	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
	if (!convert_ok) {
		cerr << "conversion to encode request failed" << endl;
		return -1;
	}
   

	xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
	    dump_instr_map_entry(instr_map_entry); 
        return -1;
    }

	// handle the case where the original instr size is different from new encoded instr:
	if (olen != xed_decoded_inst_get_length (&xedd)) {
		
		new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
	               instr_map[instr_map_entry].new_ins_addr - olen;

		if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_CALL_NEAR, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

		if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, 
			XED_ICLASS_JMP, 64,
			xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


		xed_encoder_request_zero_set_mode(&enc_req, &dstate);
		xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
		if (!convert_ok) {
			cerr << "conversion to encode request failed" << endl;
			return -1;
		}

		xed_error = xed_encode (&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen , &olen);
		if (xed_error != XED_ERROR_NONE) {
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
			dump_instr_map_entry(instr_map_entry);
			return -1;
		}		
	}

	
	// debug prints:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry); 
	}
		
	instr_map[instr_map_entry].hasNewTargAddr = true;
	return olen;	
}


/***********************************/
/* fix_direct_br_call_displacement */
/***********************************/
int fix_direct_br_call_displacement(int instr_map_entry) 
{					

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
				   
	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	xed_int32_t  new_disp = 0;	
	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;


	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
	
	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_COND_BR && category_enum != XED_CATEGORY_UNCOND_BR) {
		cerr << "ERROR: unrecognized branch displacement" << endl;
		return -1;
	}

	// fix branches/calls to original targ addresses:
	if (instr_map[instr_map_entry].new_targ_entry < 0) {
	   int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
	   return rc;
	}

	ADDRINT new_targ_addr;		
	new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;
		
	new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size; // orig_size;

	xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

	// the max displacement size of loop instructions is 1 byte:
	xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
	if (iclass_enum == XED_ICLASS_LOOP ||  iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
	  new_disp_byts = 1;
	}

	// the max displacement size of jecxz instructions is ???:
	xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum (&xedd);
	if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
	  new_disp_byts = 1;
	}

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

	xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
	unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
    
	xed_error_enum_t xed_error = xed_encode (&xedd, enc_buf, max_size , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
		char buf[2048];		
	//	xed_decoded_inst_dump_intel_format(&xedd, buf, 2048, instr_map[instr_map_entry].orig_ins_addr);
        xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, instr_map[instr_map_entry].orig_ins_addr, 0, 0);

	    cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
  		return -1;
	}		

	new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;

	new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);
	
	xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}				

	//debug print of new instruction in tc:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}

	return new_size;
}				


/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements()
{
   // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;	

	do {
		
		size_diff = 0;

		if (KnobVerbose) {
			cerr << "starting a pass of fixing instructions displacements: " << endl;
		}

		for (int i=0; i < num_of_instr_map_entries; i++) {

			instr_map[i].new_ins_addr += size_diff;
				   
			int rc = 0;

			// fix rip displacement:			
			rc = fix_rip_displacement(i);
			if (rc < 0)
				return -1;

			if (rc > 0) { // this was a rip-based instruction which was fixed.

				if (instr_map[i].size != (unsigned int)rc) {
				   size_diff += (rc - instr_map[i].size); 					
				   instr_map[i].size = (unsigned int)rc;								
				}

				continue;   
			}

			// check if it is a direct branch or a direct call instr:
			if (instr_map[i].orig_targ_addr == 0) {
				continue;  // not a direct branch or a direct call instr.
			}


			// fix instr displacement:			
			rc = fix_direct_br_call_displacement(i);
			if (rc < 0)
				return -1;

			if (instr_map[i].size != (unsigned int)rc) {
			   size_diff += (rc - instr_map[i].size);
			   instr_map[i].size = (unsigned int)rc;
			}

		}  // end int i=0; i ..

	} while (size_diff != 0);

   return 0;
 }


//TODO: need to change following function

/*****************************************/
// find_candidate_rtns_for_translation()  
/*****************************************/
int find_candidate_rtns_for_translation(IMG img)
{
    int rc;

	// go over routines and check if they are candidates for translation and mark them for translation:

	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {	

			if (rtn == RTN_Invalid()) {//TODO: check if RTN in top 10
			  cerr << "Warning: invalid routine " << RTN_Name(rtn) << endl;
  			  continue;
			}
            if (!isTopTenRTN(rtn)){
                continue;
            }

			translated_rtn[translated_rtn_num].rtn_addr = RTN_Address(rtn);			
			translated_rtn[translated_rtn_num].rtn_size = RTN_Size(rtn);
			translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;
			translated_rtn[translated_rtn_num].isSafeForReplacedProbe = true;	

			// Open the RTN.
			RTN_Open( rtn );              

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {

    			//debug print of orig instruction:
				if (KnobVerbose) {
 					cerr << "old instr: ";
					cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) <<  endl;
					//xed_print_hex_line(reinterpret_cast<UINT8*>(INS_Address (ins)), INS_Size(ins));				   			
				}				

				ADDRINT addr = INS_Address(ins);
                			
			    xed_decoded_inst_t xedd;
			    xed_error_enum_t xed_code;							
	            
				xed_decoded_inst_zero_set_mode(&xedd,&dstate); 

				xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
				if (xed_code != XED_ERROR_NONE) {
					cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
					translated_rtn[translated_rtn_num].instr_map_entry = -1;
					break;
				}

				// Add instr into instr map:
				rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
				if (rc < 0) {
					cerr << "ERROR: failed during instructon translation." << endl;
					translated_rtn[translated_rtn_num].instr_map_entry = -1;
					break;
				}
			} // end for INS...


			// debug print of routine name:
			if (KnobVerbose) {
				cerr <<   "rtn name: " << RTN_Name(rtn) << " : " << dec << translated_rtn_num << endl;
			}			


			// Close the RTN.
			RTN_Close( rtn );

			translated_rtn_num++;

		 } // end for RTN..
	} // end for SEC...


	return 0;
}


/***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc()
{
	int cursor = 0;

	for (int i=0; i < num_of_instr_map_entries; i++) {

	  if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
		  cerr << "ERROR: Non-matching instruction addresses: " << hex << (ADDRINT)&tc[cursor] << " vs. " << instr_map[i].new_ins_addr << endl;
	      return -1;
	  }	  

	  memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);

	  cursor += instr_map[i].size;
	}

	return 0;
}


/*************************************/
/* void commit_translated_routines() */
/*************************************/
inline void commit_translated_routines() 
{
	// Commit the translated functions: 
	// Go over the candidate functions and replace the original ones by their new successfully translated ones:

	for (int i=0; i < translated_rtn_num; i++) {

		//replace function by new function in tc
	
		if (translated_rtn[i].instr_map_entry >= 0) {
				    
			if (translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES && translated_rtn[i].isSafeForReplacedProbe) {						

				RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);

				//debug print:				
				if (rtn == RTN_Invalid()) {
					cerr << "committing rtN: Unknown";
				} else {
					cerr << "committing rtN: " << RTN_Name(rtn);
				}
				cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;

						
				if (RTN_IsSafeForProbedReplacement(rtn)) {

					AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);							

					if (origFptr == NULL) {
						cerr << "RTN_ReplaceProbed failed.";
					} else {
						cerr << "RTN_ReplaceProbed succeeded. ";
					}
					cerr << " orig routine addr: 0x" << hex << translated_rtn[i].rtn_addr
							<< " replacement routine addr: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;	

					dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);												
				}												
			}
		}
	}
}


//TODO: need to change a function. max_rtn_count = 10

/********************************************************/
/*************** allocate_and_init_memory ***************/
/********************************************************/ 
int allocate_and_init_memory(IMG img) 
{
	// Calculate size of executable sections and allocate required memory:
	//
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;


		if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
			lowest_sec_addr = SEC_Address(sec);

		if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
			highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

		// need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			if (rtn == RTN_Invalid())
				continue;

			max_ins_count += RTN_NumIns  (rtn);
			max_rtn_count++;
		}
	}

	max_ins_count *= 4; // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.
	
	// Allocate memory for the instr map needed to fix all branch targets in translated routines:
	instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
	if (instr_map == NULL) {
		perror("calloc");
		return -1;
	}


	// Allocate memory for the array of candidate routines containing inlineable function calls:
	// Need to estimate size of inlined routines.. ???
	translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
	if (translated_rtn == NULL) {
		perror("calloc");
		return -1;
	}


	// get a page size in the system:
	int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
      perror("sysconf");
	  return -1;
	}

	ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    int tclen = 2 * text_size + pagesize * 4;   // need a better estimate???

	// Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:		
	char * addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if ((ADDRINT) addr == 0xffffffffffffffff) {
		cerr << "failed to allocate tc" << endl;
        return -1;
	}
	
	tc = (char *)addr;
	return 0;
}


/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
VOID ImageLoad(IMG img, VOID *v)
{
	// debug print of all images' instructions
	//dump_all_image_instrs(img);

    // Step 0: Check the image and the CPU:
	if (!IMG_IsMainExecutable(img))
		return;

	int rc = 0;
	

	// step 1: Check size of executable sections and allocate required memory:	
	rc = allocate_and_init_memory(img);
	if (rc < 0)
		return;

	cout << "after memory allocation" << endl;

	
	// Step 2: go over all routines and identify candidate routines and copy their code into the instr map IR:
	rc = find_candidate_rtns_for_translation(img);
	if (rc < 0)
		return;

	cout << "after identifying candidate routines" << endl;	 
	
	// Step 3: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
	rc = chain_all_direct_br_and_call_target_entries();
	if (rc < 0 )
		return;
	
	cout << "after calculate direct br targets" << endl;

	// Step 4: fix rip-based, direct branch and direct call displacements:
	rc = fix_instructions_displacements();
	if (rc < 0 )
		return;
	
	cout << "after fix instructions displacements" << endl;


	// Step 5: write translated routines to new tc:
	rc = copy_instrs_to_tc();
	if (rc < 0 )
		return;

	cout << "after write all new instructions to memory tc" << endl;

   if (KnobDumpTranslatedCode) {
	   cerr << "Translation Cache dump:" << endl;
       dump_tc();  // dump the entire tc

	   cerr << endl << "instructions map dump:" << endl;
	   dump_entire_instr_map();     // dump all translated instructions in map_instr
   }


	// Step 6: Commit the translated routines:
	//Go over the candidate functions and replace the original ones by their new successfully translated ones:
	commit_translated_routines();	

	cout << "after commit translated routines" << endl;
   
}

/* ===================================================================== */
/* Our ex3 functions	                                                 */
/* ===================================================================== */
VOID setTopRtnAddr()
{
	int j=0,fd=0;
	
	 // open the profile file and map it to memory:
    fd = open("__profile.map", O_RDONLY);
    if (fd == -1) {
        cerr << "no profile file found " << endl;
        exit(1);
    }
	
	
	//GET THE TABLE SIZE TO READ IT
	instrTable = (instr_table_t *)mmap(0, sizeof(instr_table_t), PROT_READ , MAP_SHARED | MAP_FILE , fd, 0);
    if ((ADDRINT) instrTable == 0xffffffffffffffff) {
        cerr << "mmap" << endl;
        exit(1);
    }
	UINT64 table_size = instrTable[0].count;
	

    instrTable = (instr_table_t *)mmap(0, table_size * sizeof(instr_table_t), PROT_READ , MAP_SHARED | MAP_FILE , fd, 0);
    if ((ADDRINT) instrTable == 0xffffffffffffffff) {
        cerr << "mmap" << endl;
        exit(1);
    }
	j++;
	for (int i=0; i<NUMBER_TC_RTNS; i++)
	{
		/*UINT64 rtn_cnt = */ instrTable[j++].count;
		UINT64 addr = instrTable[j++].count;
		UINT64 bbl_list_size = instrTable[j++].count;
		for (UINT64 i=0; i<bbl_list_size; i++)
		{
			j++;
		}
		top10_rtn_addr.push_front(addr);
		//cerr << StringHex(addr, 1) << "   And the number is: " << rtn_cnt << endl;
	}
	
	//fd.close();
}


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool translated routines of an Intel(R) 64 binary"
         << endl;
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}


INT32 Usage1()
{
	cerr << "Please use the pintool with either -prof or -opt knobs" << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
	// Initialize symbol table code, needed for rtn instrumentation
	PIN_InitSymbols();

	// Initialize pin
	if (PIN_Init(argc, argv))
	{
		Usage();
		return 0;
	}
	
	if(KnobProfile){
 
		// Register Trace to be called to instrument trace
		TRACE_AddInstrumentFunction(TRACEINFO, 0);
		// Register Fini to be called when the application exits
		PIN_AddFiniFunction(Fini, 0);
        
        // Start the program, never returns
	    PIN_StartProgram();
        return 0;
	}
    
    //run in probe mode and generate the binary code of the top 10 routines
    else if(KnobGenerateBinary){ 
		//Set RTNs
		setTopRtnAddr();
		
        // Register ImageLoad
	    IMG_AddInstrumentFunction(ImageLoad, 0);

         // Start the program, never returns
         PIN_StartProgramProbed();
        return 0;
    }
    else
        PIN_StartProgram();
    
	  //  return Usage1();
    return 0;
}

