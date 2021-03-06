/*! \mainpage Documentation of Daq Program
 * 
 * \section intro_sec Introduction
 *
 * Daq program to capture event from AMC40 or DemoBoard<Br>
 * use protocole UDP
 *
 * \section Download_sec	Download
 * 
 * "svn svn+ssh://user_name@svn.in2p3.fr/dpga/Soft/FirmwareTests/ServeurUdp/DaqPfRingc++"
 * 
 * \section Compilation_sec Compilation
 * 
 * requirement cmake version >= 2.8 <br>
 * cd build <br>
 * cmake .. <br>
 * make <br>
 * 
 * \section install_sec Installation
 * 
 * 
 * \section copyright Copyright and License
 * Laboraroite de Physique de Clermont-Ferrand PLUS
 * \image html logo1.jpg
 *
 * <BR><BR>
 *
 */
/**
 * \file daq.cpp
 * \brief Programme DAQ For DPGA 
 * \author Daniel Lambert
 * \version 1.0.0
 * \date 10/07/2017
 * contact daniel.lambert@clermont.in2p3.fr
 * Daq program
 * 
 */

#include <sstream>
#include <iostream>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <zlib.h>
#include <chrono>

#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <sys/msg.h>
#include <time.h>
#include <sys/wait.h>
#include "ipcdaq.h"

#include "color.h"
#include "pfutils.h"
#include "frame.h"
#include "GenericTypeDefs.h"
#include "readring.h"
#include "Version.h"
#include "logit.h"
#include "eventbuilder.h"

//#define  VERSION_DAQ "1.1.0  " __DATE__  " " __TIME__

#define ALARM_SLEEP	 1
#define ALARM_STOP	 10
#define ALARM_START	 2
#define DEFAULT_SNAPLEN  9000 //128
#define MAX_NUM_THREADS  64
#define MAX_IFCE	 2
#define MAX_RECORD	 30000

std::vector<class cReadRing *> pReadRing;
std::vector <std::thread> ThreadList;

enum TSTATE {sIDLE = 0, sPAUSE=1, sWAIT=2 , sSTART=3};

int StateAlarm = sIDLE;

int do_shutdown=0;
const unsigned char BufferStart[2] 	= {0xaa,0xdc};
const unsigned char BufferStop[2] 	= {0xaa,0xcd};
const std::string DEFAULT_DEVICE[MAX_IFCE]  =   {"eno1","eno2"};
struct timeval startTime;
static int32_t thiszone;
unsigned int 	Ifce=0;
u_int DurationPause 	= ALARM_STOP;
u_int DurationRun 	= ALARM_START;
int CountAlarm;
bool SendPause;
bool DumpFile;
bool eventBuilder;
bool Rollover;
bool Pause=false;
int s;
struct sockaddr_in si_other;
bool RunDaq= false;

ShmRingBuffer<sStatFrame> 		*shdNet;
ShmRingBuffer<SharedMemory> 	*shdmem;
ShmRingBuffer<sHistoSrout> 	*shdsrout;

int g_msgid;
std::thread *ipc;
cEventBuilder *pEventBuilder;
loglevel_e loglevel = logERROR;

void init_ctrldaq(const char *Addr) {
  /****************************************************************************************/
  /**																												**/
  /****************************************************************************************/
  s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s==-1) perror("Socket Transmit failed");
  int disable = 1;
  if (setsockopt(s, SOL_SOCKET, SO_NO_CHECK, (void*)&disable, sizeof(disable)) < 0) {
    perror("setsockopt failed");
  }
  memset((char *) &si_other, 0, sizeof(si_other));
  si_other.sin_family = AF_INET;
  si_other.sin_port = htons(60000);
  si_other.sin_addr.s_addr=inet_addr(Addr);

  log(logINFO,true) << "ip start/stop command Address = " << Addr;
  /*** Put AMC no Daq pause ***/

  if (sendto(s, BufferStart,2,0,(struct sockaddr*)&si_other,sizeof(si_other))==-1) {
    log(logERROR,true) << "send error";
    perror("send()");
    exit(errno);
  }
}

void PauseStartFrame(bool start)
/****************************************************************
 * 
 * 
 ***************************************************************/ 
{
  if ((start) && (Pause)) {
    log(logINFO,true) << "Daq Start ....";
    Pause = false;
    if (sendto(s, BufferStart,2,0,(struct sockaddr*)&si_other,sizeof(si_other))==-1) {
      perror("send()");
      exit(errno);
    }
  }
  else if (!Pause) {
    log(logINFO,true) << "Pause request ...  ";
    Pause = true;
    if (sendto(s, BufferStop,2,0,(struct sockaddr*)&si_other,sizeof(si_other))==-1) {
      perror("send()");
      exit(errno);
    }
  }
}

void VersionInfo()
{
  log(logINFO,true) << FgColor::yellow() << "Program Daq " << __PROGRAM_VERSION_STRING__ << "  Gitrev " << __GITVER__
	    << " build at " << __DATE__ << "  " << __TIME__ << FgColor::white();
  log(logINFO,true) << "Author Daniel Lambert <daniel.lambert@clermont.in2p3.fr>";
  log(logINFO,true) << "Shm Library " << getVersionShm();
  log(logINFO,true) << "DecodeFrame Library " << getVersionDecodeFrame();
}

void printHelp(void) {
  VersionInfo();

  printf("\n-h              Print this help\n");
  printf("-a              Active packet wait\n");
  printf("-e <direction>  0=RX+TX, 1=RX only, 2=TX only\n");
  printf("-l <len>        Capture length (default 9000) max capability of ethernet interface\n");
  printf("-i <device>     Device name (eno1,eno2,dependent linux system\n use ifconfig or ip command \n");
  printf("-m              Long packet header (with PF_RING extensions)\n");
  printf("-v              Verbose\n");  
  printf("-b <cpu %%>  	CPU pergentage priority (0-99) ?????\n");
  printf("-P <delay>  		Pause delay (sec) \n");
  printf("-S <delay>  		Run delay	(sec)	\n");
  printf("-g <id:id...>   Specifies the thread affinity mask. Each <id> represents\n"
	 "               	the core id where the i-th will bind. Example: -g 7:6:5:4\n"
	 "               	binds thread <device>@0 on coreId 7, <device>@1 on coreId 6\n"
	 "               	and so on.\n");
  printf("-f <Path_to_file>	Specifies the path of file to record data\n");
  printf("-R 					Roll over file \n");
  printf("-z 					compress file\n");
  printf("-o					Record Mode 0=Header,1=Rawdata+header,2=Rawdata+header+ethernet header\n\n\n");
  printf("Example bin/daqdpga -i eno1 -i eno2 -g 1:2:3:4:5:6:7:8 -g 20:21:22:23:24:25:26:27 -a -o 1 -f /datas1/run0005\n");
}

void PrintStat_v1()
{
  double thptTot=0;
  double thptEno1=0;
  double thptEno2=0;
  int nBoards = 0;
  std::sort(pReadRing.begin(), pReadRing.end(), [](cReadRing * one, cReadRing * two){return one->GetStats()->MemFeId < two->GetStats()->MemFeId;});
  std::vector<class cReadRing *>::iterator it;
  std::cout << "========================" << std::endl;
  for (it= pReadRing.begin();it != pReadRing.end();++it) {
    class cReadRing *pIt = *(it);
    bool hasPkts = pIt->PrintStats(shdNet);
    //std::cout << "debug: in daq.cpp -> PrintStat_v1() " << std::hex<<(u16) pIt->GetStats()->MemFeId<<std::dec << "  " << hasPkts << "  " << nBoards << std::endl;
    thptTot+=pIt->GetStats()->thpt;
    std::string eno = pIt->GetDev().substr(0, pIt->GetDev().find("@"));
    //std::cout << "Debug: " << pIt->GetDev() << "  " << eno << std::endl;
    if(eno=="eno1") {
      thptEno1+=pIt->GetStats()->thpt;
    } else if (eno=="eno2") {
      thptEno2+=pIt->GetStats()->thpt;
    } else {
      std::cout << FgColor::red() << "In daq.cpp PrintStat_v1(): we should never end up here --> investigate" << FgColor::white() << std::endl;
      exit(0);
    }
    if(hasPkts) {
      ++nBoards;
    }
  }
  fprintf(stderr,
	  "%sNumber of ASM Boards = %d   Total transfer rate = %.2f Mbit/sec (eno1: %.2f Mbit/sec, eno2: %.2f Mbit/sec)%s\n",
	  FgColor::magenta(),
	  nBoards,
	  thptTot,
	  thptEno1,
	  thptEno2,
	  FgColor::white());
  pEventBuilder->PrintStats();
} 


void PrintStatsEnd() 
/**********************************************************
 *
 * 
 * ********************************************************/ 
{
  u64 SumFrameRec=0;
  u64 SumFrameAsm=0;
  u64 SumFRameLost=0;
  u64 MaxFrameAmc=0;
  double Purcent;

  SumFrameRec  = 0;
  SumFrameAsm  = 0;
  SumFRameLost = 0;
  std::vector<class cReadRing *>::iterator it;

  for (it= pReadRing.begin();it != pReadRing.end();++it) {
    class cReadRing *pIt = *(it);
    struct sStatFrame *StatFrame  = pIt->GetStats();

		
    if (StatFrame->NbFrameRec>0)  Purcent = (double)StatFrame->NbFrameAsmLost/(double)StatFrame->NbFrameRec;
    else Purcent= 0.0;
    printf("%s\t [0x%x] Frame rec=%8llu \t FrameAsm = %8llu \t FrameLost = %s%6llu %s (%2.2f %%) \t Frame Amc=%8d \t NumFrameOk=%8llu NumTriggerCountsFromASM=%s%6llu%s (%2.4f %%) ErrId=%8llu Under=%4llu Over=%4llu Tc=%d (%d)\n",
	   pIt->GetDev().c_str(),
	   StatFrame->MemFeId,
	   StatFrame->NbFrameRec,
	   StatFrame->NbFrameAsm,
	   FgColor::red(),
	   StatFrame->NbFrameAsmLost,
	   FgColor::white(),
	   Purcent*100,
	   StatFrame->NbFrameAmc,
	   StatFrame->NumFrameOk,
	   FgColor::red(),
	   StatFrame->NumTriggerCountsFromASM,
	   FgColor::white(),
	   StatFrame->NumTriggerCountsFromASM/float(StatFrame->NumFrameOk)*100,
	   StatFrame->ErrId,
	   StatFrame->UnderSize,
	   StatFrame->OverSize,
	   pIt->GetTriggerCount(),
	   StatFrame->TriggerCountOrig);
		
    SumFrameRec  += StatFrame->NbFrameRec;
    SumFrameAsm  += StatFrame->NbFrameAsm;
    SumFRameLost += StatFrame->NbFrameAsmLost;
	
    if (MaxFrameAmc  < StatFrame->NbFrameAmc) MaxFrameAmc = StatFrame->NbFrameAmc;
  }
  if (SumFrameRec > 0) Purcent = (double)SumFRameLost*100/(double)SumFrameRec;
  else Purcent=0;
  printf("Totaux \t Frame rec=%8llu \t FrameAsm = %8llu \t FrameLost = %8llu (%2.4f %%)\t Frame Amc=%8llu\n\n",
	 SumFrameRec,SumFrameAsm,SumFRameLost,Purcent,MaxFrameAmc);
	
}

void sigproc(int sig) {
  /**********************************************************
   *
   * 
   * ********************************************************/ 
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  PrintStatsEnd();
  fprintf(stderr, "Shutting down sockets...\n");
  do_shutdown = 1;
	
  printf("Waiting Stop Thread\n"); 
  for (auto &pIt : pReadRing) pIt->Stop();
  printf("Stopping Thread \t");
  for (auto &itthread : ThreadList) {
    printf(".");
    itthread.join();
  }

  printf("\n");
  if ( -1 == msgctl( g_msgid, IPC_RMID, NULL ) )
    perror( "msgctl" );
  ipc->join(); 
  msgctl(g_msgid, IPC_RMID,0);           
  if (ipc) 	delete (ipc);
  if (shdmem) delete (shdmem);
  if (shdNet) delete (shdNet);
  if (shdsrout) delete (shdsrout);
  exit(0);
}

void my_sigalarm(int sig) {
  /****************************************************************
   * 
   * 
   ***************************************************************/ 
  if (do_shutdown)
    return;
  bool Running = false;
  for (auto &pIt : pReadRing) Running |= pIt->GetRunning();

  if (Running) 
    switch (StateAlarm) {
    case sIDLE 		: 	if (SendPause && (CountAlarm++ > 10)) {
	CountAlarm=0;
	PauseStartFrame(false);
	StateAlarm = sPAUSE;
	printf("%s Send Pause....%s\n",FgColor::yellow(),FgColor::white());
      }
      //std::cout << "debug: in daq.cpp -> my_sigalarm -> case sIDLE" << std::endl;
      if (RunDaq) PrintStat_v1();
      break;
									
    case sPAUSE		:	if (SendPause && (CountAlarm++ > 3)) {
	CountAlarm=0;
	if (Rollover) {
	  for (auto &pIt : pReadRing) pIt->InitDumpFile();
	  StateAlarm = sWAIT;
	}
	else StateAlarm = sSTART;
      }
      //std::cout << "debug: in daq.cpp -> my_sigalarm -> case sPAUSE" << std::endl;
      if (RunDaq) PrintStat_v1();
      break;
    case sWAIT		: 	StateAlarm = sSTART;
      break;
    case sSTART		: 	PauseStartFrame(true);
      printf("%s Send start....%s\n",FgColor::yellow(),FgColor::white());
      StateAlarm = sIDLE;
      break;
    } 
		
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);

}

int parse_bpf_filter(char *filter_buffer, u_int caplen) {
	
  struct bpf_program filter;
  if(pcap_compile_nopcap(caplen,        /* snaplen_arg */
                         DLT_EN10MB,    /* linktype_arg */
                         &filter,       /* program */
                         filter_buffer, /* const char *buf */
                         0,             /* optimize */
                         0              /* mask */
                         ) == -1) {
    return -1;
  }

  if(filter.bf_insns == NULL)
    return -1;

  return 0;
}

void IpcReceivedMsg()
{
  /************************************************************************
   * 
   * 
   * **********************************************************************/
  MESSAGE msg;
  string s;

  msg.nMsgType = 0;
  std::cout << "msg id = "<< g_msgid << std::endl;
   
  while (!do_shutdown) {
    if (msgrcv( g_msgid, &msg, MAX_MESSAGE, 0, 0 ) >0)	{
      printf( "received '%lu' %s@ %d \n", msg.nMsgType,msg.arg.sText,msg.cmd);
      switch (msg.cmd) {
      case IPCNONE : std::cout << "None" << std::endl;break;
      case IPCDAQ  :
                    if (!RunDaq) {
                        pEventBuilder->setNbEventDisplay(msg.arg.val);
                        pEventBuilder->StartDaq();
                        for (auto &it : pReadRing) {
                            it->setNbEventDisplay(msg.arg.val);
                            it->StartDaq();
                        }
                    }
                    RunDaq = true;
                    std::cout << "Daq  " << RunDaq << std::endl;
                    break;
      case IPCSTOP      :   RunDaq = false;
                            PrintStatsEnd();
                            std::cout << "Stop  " << RunDaq << std::endl;
                            break;
      case IPCINTERVAL  :   for (auto &it : pReadRing) it->setNbEventDisplay(msg.arg.val);
                            pEventBuilder->setNbEventDisplay(msg.arg.val);
                            std::cout << "interval " << msg.arg.val << std::endl;
                            break;
      case IPCRECORD    :   s = msg.arg.sText;
                            log(logINFO,true) << " Record to file  " << s;
                            if   (!eventBuilder) for(auto &it : pReadRing) it->setFile(&s,true);
                            else pEventBuilder->setFile(&s,true);
                            break;
      case IPCWITHOUTFILE : for (auto &it : pReadRing) it->noFile(); break;//pEventBuilder->noFile();break;
      case IPCNBSAMPLES :  for (auto &it : pReadRing) it->setNbSamples(msg.arg.val);
                           pEventBuilder->setNbSamples(msg.arg.val);
                           log(logINFO,true) << "NbSamples " << msg.arg.val;break;
      case IPCDEBUG     :  loglevel = (loglevel_e) msg.arg.val;break;
	
      };
    }
    else usleep(100);
    std::cout << "Value Daq  " << RunDaq << std::endl;
  }
}

int main(int argc, char* argv[]) {
  /************************************************************************
   * 
   * 
   * **********************************************************************/
  /*	std::string BpfFilter[2][8] = {{"dst 192.168.3.17 and  udp port 60000","dst 192.168.3.18 and  udp port 60001",
	"dst 192.168.3.19 and  udp port 60002","dst 192.168.3.20 and  udp port 60003",
	"dst 192.168.3.21 and  udp port 60004","dst 192.168.3.22 and  udp port 60005",
	"dst 192.168.3.23 and  udp port 60006","dst 192.168.3.24 and  udp port 60007"},
	{"dst 192.168.2.17 and  udp port 60000","dst 192.168.2.18 and  udp port 60001",
	"dst 192.168.2.19 and  udp port 60002","dst 192.168.2.20 and  udp port 60003",
	"dst 192.168.2.21 and  udp port 60004","dst 192.168.2.22 and  udp port 60005",
	"dst 192.168.2.23 and  udp port 60006","dst 192.168.2.24 and  udp port 60007"}
	};
  */
  /*std::string BpfFilter[2][8] = {{"src 192.168.3.129 and  udp port 60000","src 192.168.3.130 and  udp port 60000",
    "src 192.168.3.131 and  udp port 60000","src 192.168.3.132 and  udp port 60000",
    "src 192.168.3.133 and  udp port 60000","src 192.168.3.134 and  udp port 60000",
    "src 192.168.3.135 and  udp port 60000","src 192.168.3.136 and  udp port 60000"},
    {"src 192.168.2.129 and  udp port 60000","src 192.168.2.130 and  udp port 60000",
    "src 192.168.2.131 and  udp port 60000","src 192.168.2.132 and  udp port 60000",
    "src 192.168.2.133 and  udp port 60000","src 192.168.2.134 and  udp port 60000",
    "src 192.168.2.135 and  udp port 60000","src 192.168.2.136 and  udp port 60000"}
    };
  */	
										 
  char *device[MAX_IFCE];
  char c;
  char *bind_mask[MAX_IFCE];
  char *bpfFilter = NULL; 
  int NbEventDisplay=1000;
 
  u_int TotalChannels=0;

  u_int verbose = 0;

  u_int num_channels[MAX_IFCE] = {1,1};
  eventBuilder = false;
	
  u_int Ifce = 0,NumMask = 0;
  bool compress = false;
  eModefile ModeFile = ALL;
  int snaplen = DEFAULT_SNAPLEN;//, rc;
  packet_direction direction = rx_only_direction;

  std::string File;
  int wait_for_packet=1;
  int use_extended_pkt_header=0;
  bool udpSend = false;
  u_int16_t cpu_percentage = 0;
  u_int32_t version;
  u_int32_t flags = 0;
  string udpAddr;
  eventBuilder = false;
  //printf("%s",BgColor::black);
  
  for (u_int NumIfce=0;NumIfce < MAX_IFCE;++NumIfce) {
    device[NumIfce] = NULL;
    bind_mask[NumIfce] = NULL;
  }
  
  //  pfring *ring[MAX_NUM_RX_CHANNELS];

  int threads_core_affinity[MAX_IFCE][MAX_NUM_RX_CHANNELS]; // MAX_NUM_RX_CHANNELS defined in pfring.h

  memset(threads_core_affinity, -1, sizeof(threads_core_affinity));
  startTime.tv_sec = 0;
  thiszone = gmt_to_local(0);
  unsigned int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  if (argc < 2) {
    printHelp();
    exit(0);
  }

  VersionInfo();

  while((c = getopt(argc,argv,"hae:l:i:mv:b:P:S:g:f:Rzo:n:EU:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'e':
      switch(atoi(optarg)) {
      case rx_and_tx_direction: direction = rx_and_tx_direction;break;
      case rx_only_direction: direction = rx_only_direction;break;
      case tx_only_direction: direction = tx_only_direction;break;
      }
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'i':
      device[Ifce++] = strdup(optarg);
      break;
    case 'm':
      use_extended_pkt_header = 1;
      break;
    case 'v':
      verbose = atoi(optarg);
      loglevel = (loglevel_e) verbose;
      break;
    case 'b':
      cpu_percentage = atoi(optarg);
      break;
    case 'P':
      DurationPause = atoi(optarg);
      SendPause = true;
      break;      
    case 'S' :
      DurationRun = atoi(optarg);
      SendPause = true;
      break;
    case 'g':
      bind_mask[NumMask++] = strdup(optarg);
      printf("binsmak =%s\n",bind_mask[NumMask-1]);
      break;
    case 'f':
      File =optarg;
      umask(0000);
      mkdir(File.c_str(),0777);
      DumpFile = true;
      break;		
    case 'R':
      Rollover = true;
      break;
    case 'E':
      eventBuilder = true;
      std::cout << FgColor::yellow() << "EventBuilder Actived"  << FgColor::white() << std::endl;
      break;      
    case 'U':
      udpSend = true;
      udpAddr = optarg;
      std::cout << FgColor::yellow() << "Udp Actived with " <<  optarg << FgColor::white() << std::endl;
      break;            
    case 'z':
      compress = true;
      printf("Mode compressed \n");
      break;
    case 'n' :
      NbEventDisplay = atoi(optarg);
      break;
    case 'o':
      switch (atoi(optarg)) {
      case 0 : ModeFile = HEADER;printf("Record File Mode Header\n");break;
      case 1 : ModeFile = RAWDATA;printf("Record File Mode RawData\n");break;
      case 2 : ModeFile = ALL;printf("Record File Mode All Data\n");break;
      }
      break;
    }
  }

  //  if(verbose) watermark = 1;
  
  for (u_int NumIfce=0;NumIfce < Ifce;++NumIfce) {
    if(device[NumIfce] == NULL) device[NumIfce] = (char *) DEFAULT_DEVICE;
  }

  bind2node(threads_core_affinity[0][0]);
	
  init_ctrldaq("192.168.2.50"); 
	
  flags |= PF_RING_PROMISC; /* hardcode: promisc=1 */
  flags |= PF_RING_ZC_SYMMETRIC_RSS;  /* Note that symmetric RSS is ignored by non-ZC drivers */
  if(use_extended_pkt_header) flags |= PF_RING_LONG_HEADER; 
  
  if(bpfFilter != NULL) {
    if (parse_bpf_filter(bpfFilter, snaplen) == 0) {
      printf("Successfully set BPF filter '%s'\n", bpfFilter);
    } else
      printf("Error compiling BPF filter '%s'\n", bpfFilter);
  }
  
  int base = 0;
  shdmem = new ShmRingBuffer<SharedMemory>(CAPACITY,true,SHM_ASM_DATA);
  shdNet = new ShmRingBuffer<sStatFrame>(CAPACITY,true,SHM_NETWORK);
  shdsrout = new ShmRingBuffer<sHistoSrout>(CAPACITY,true,SHM_SROUT);
  
  log(logINFO,true) << "Shm Library " << shdmem->getVersion();
  log(logINFO,true) << "DecodeFrame library ";
	
  printf("Size Stats net %lu\n",sizeof (sStatFrame));
	
  for (u_int NumIfce=0;NumIfce < Ifce;++NumIfce) {
    printf("Capturing from %s\n", device[NumIfce]);
		
    pfring *ring0 = pfring_open(device[NumIfce], snaplen, flags);
    if(ring0 == NULL) {
      printf("Error openning ring %s %s\n",device[NumIfce],strerror(errno));
      return(0);
    }
    else
      num_channels[NumIfce] = pfring_get_num_rx_channels(ring0);
    pfring_version(ring0, &version);  
		
    if (NumIfce == 0)
      printf("Using PF_RING v.%d.%d.%d\n",(version & 0xFFFF0000) >> 16,(version & 0x0000FF00) >> 8,version & 0x000000FF);
    pfring_close(ring0);
		
    //		num_channels[NumIfce] = pfring_open_multichannel(device[NumIfce], snaplen, flags, &ring[base]);
    base += num_channels[NumIfce];
    if(num_channels[NumIfce] <= 0) {
      fprintf(stderr, "pfring_open_multichannel() returned %d [%s]\n", num_channels[NumIfce], strerror(errno));
      return(-1);
    }
    if (num_channels[NumIfce] > MAX_NUM_THREADS) {
      log(logWARNING,true) << "WARNING: Too many channels (" << num_channels[NumIfce] <<"), using " << MAX_NUM_THREADS << " channels";
      num_channels[NumIfce] = MAX_NUM_THREADS;
    } else if (num_channels[NumIfce] > numCPU) {
      printf("WARNING: More channels (%d) than available cores (%d), using %d channels\n", num_channels[NumIfce], numCPU, numCPU);
      num_channels[NumIfce] = numCPU;
    } else  {
      printf("Found %d channels\n", num_channels[NumIfce]);
    }
	
    if (NumIfce ==0) {    // Execute one time
			
    }

    if(bind_mask[NumIfce] != NULL) {
      char *id = strtok(bind_mask[NumIfce], ":");
      int idx = 0;

      while(id != NULL) {
	threads_core_affinity[NumIfce][idx++] = atoi(id) % numCPU;
	if(idx >= MAX_NUM_THREADS) break;
	id = strtok(NULL, ":");
      }
    }
    TotalChannels += num_channels[NumIfce];
  }
	
  bool FileEventBuilder = DumpFile & eventBuilder;
  pEventBuilder = new cEventBuilder(10,File,shdmem,numCPU,FileEventBuilder,udpAddr.c_str());	
  std::thread th(&cEventBuilder::Run, pEventBuilder);
  usleep(100);
  pEventBuilder->SetOnlyHeader(ModeFile);
  pEventBuilder->setNbEventDisplay(NbEventDisplay);
  log(logINFO,true) << "udpsend = " << udpSend;
  pEventBuilder->setUpdSend(udpSend);
  
  u_int i =0;
  bool FileByCard = DumpFile & not eventBuilder;	
  for (unsigned int Interface=0; Interface<	Ifce;++Interface) {	
    for (unsigned int index = 0; index < num_channels[Interface]; index++,i++)  {
      pReadRing.push_back(new class cReadRing(index,device[Interface],snaplen,flags,threads_core_affinity[Interface][index],&File,shdmem,shdsrout,
					      FileByCard,direction,wait_for_packet,numCPU,pEventBuilder));
      if (!pReadRing.back()) std::cout <<" Error Creating thread " << i << "  " << pReadRing[i] << std::endl;
      pReadRing.back()->setNbEventDisplay(NbEventDisplay);
      ThreadList.push_back(pReadRing.back()->MemberThread());
      pReadRing.back()->SetOnlyHeader(ModeFile);
      pReadRing.back()->SetCompress(compress);
      pReadRing.back()->setEventBuilder(eventBuilder);
      usleep(100);
    }

    if(cpu_percentage > 0) {
      if(cpu_percentage > 99) cpu_percentage = 99;
      pfring_config(cpu_percentage);
    }
  }

	
  /**********************************************************************************************************/
  /* Create IPc Message and thread																									 */
  /**********************************************************************************************************/
	
  g_msgid = msgget( KEYREQUEST, 0644 | IPC_CREAT );
  if ( -1 == g_msgid )  {
    perror( "msgget" );
  }
    
  ipc = new std::thread(IpcReceivedMsg);  

  //if (0 == fork()) IpcReceivedMsg();
	
  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  for (unsigned int z=0;z<Ifce;z++) 		free(device[z]);
  for (unsigned int z=0;z<NumMask;z++) 	free(bind_mask[z]);
  while (!do_shutdown) sleep(1);

  return(0);
}
