#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include "pin.H"
#include <map>
#include <list>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PROFILE_NAME "__profile.map"
#define MAX_FINE_NAME_SIZE 30

KNOB<BOOL>   KnobProfile(KNOB_MODE_WRITEONCE,    "pintool",
    "prof", "0", "Profiling run");
KNOB<BOOL>   KnobInstrument(KNOB_MODE_WRITEONCE,    "pintool",
    "inst", "0", "Profiling run");



using namespace std;
ofstream outFile;

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
// Types and structures
/* ======================================= */
typedef struct _instr_table_t {
    UINT64 count;
} instr_table_t;


/* ======================================= */
// Global variables
/* ======================================= */

instr_table_t *instrTable = NULL; 
list<RTN_Class*> rtn_list;
USIZE instrCountTableSize = 0;


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

VOID Usage()
{
	cerr << "Please use the pintool with either -prof or -opt knobs" << endl;
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
    instrCountTableSize = rtn_list.size() + Edge_Class::cnt;

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
	for (list<RTN_Class*>::iterator rtn_it = rtn_list.begin(); rtn_it != rtn_list.end(); rtn_it++) {

		UINT64 count = instrTable[j++].count += *((*rtn_it)->getIcountPtr()) ;
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
	}
	
	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

