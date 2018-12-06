#include <thread>
#include <iostream>
#include <string.h>
#include <mutex>
#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <unistd.h>
#include <sstream>
#include <fstream>
#include <ext/stdio_filebuf.h>
#include <semaphore.h>
#include <time.h>
#include <sys/time.h>
#include "zlib.h"
//#include <bsd/stdio.h>

//#include "common.h"

#include "readring.h"
#include "color.h"
#include "ringshm.h"
#include "shdmem.h"
#include "decodeframe.h"



using namespace std;
double delta_time (struct timeval * now,struct timeval * before);

/*
static int gzip_cookie_write(void *cookie, const char *buf, int size) {
  return gzwrite((gzFile)cookie, (voidpc)buf, (unsigned) size);
}

static int gzip_cookie_close(void *cookie) {
  return gzclose((gzFile)cookie);
}
*/
pcap_dumper_t *dump_open(pcap_t *pcap, const char *path, int want_gzip) {
	
  if (want_gzip) {
 //   gzFile z = gzopen(path, "w");
    FILE *fp = NULL;//= funopen(z, NULL, gzip_cookie_write, NULL, gzip_cookie_close);
    return pcap_dump_fopen(pcap, fp);
  } else {
    return pcap_dump_open(pcap, path);
  }
}

cReadRing::cReadRing(int index,string dev,int caplen,u_int32_t flags,int threads_core_affinity,string *File,ShmRingBuffer<SharedMemory> *shdmem,
		     ShmRingBuffer<sHistoSrout> *shdrout,bool dumpfile,packet_direction direction,int wait_for_packet,unsigned int numcpu,cEventBuilder *peventbuilder) :
                     DecodeFrame(),the_thread()
																			
/************************************************
* 
* 
***********************************************/
{
  int rc;
  ShdMem 	= shdmem;
  ShdSrout = shdrout;
  Index 	= index;
  Dev 		= dev + "@" + to_string(index);
  ThreadsCoreAffinity = threads_core_affinity;
  DumpFile = dumpfile;
  Direction = direction;
  Cptfile = 0;
  WaitForPacket = wait_for_packet;
  NumCpu = numcpu;
  Running = false;
  Compress = false;
  FileMode = ALL;
  TriggerCount=0;
  pEventBuilder = peventbuilder;	
  std::stringstream sstream; 
  sstream << std::hex << Index;
  std::string result = sstream.str();
  FileName = *File +  "/MyFile_" + Dev ;
  if (DumpFile) {
    InitDumpFileError();
    InitDumpFile();
  }
    
  Ring = pfring_open(Dev.c_str(), caplen, flags);

  if(Ring == NULL) {
    log(logERROR,true) << "Error Openning Ring %s " << Dev.c_str();
  }
  log(logDEBUG4,true) << "Ring = " << Ring ;
	
  std::string AppName = "Daq DPGA Multi Channel " + Dev;
  if (pfring_set_application_name(Ring, (char *) AppName.c_str()) < 0) {
      log(logERROR,true) << "Error Apllication Name";
  }

  if((rc = pfring_set_direction(Ring, direction)) != 0) {
    log(logERROR,true) << "pfring_set_direction returned " << rc << " [direction=" << direction << "d] (you can't capture TX with ZC)";
  }
  pfring_enable_ring(Ring);

  StatFrame = (struct sStatFrame *) malloc(sizeof(sStatFrame)); 
  hSrout = (struct sHistoSrout *) malloc(sizeof(sHistoSrout));
  memset(hSrout,0,sizeof(sHistoSrout));
  if (StatFrame == NULL) {log(logERROR,true) << "Error allocating memory StatFrame";}
  memset(StatFrame,0,sizeof(sStatFrame));
  DaqStarted = false;
	
}


void cReadRing::StartDaq()
/************************************************
 *
 * 
 * 
 ***********************************************/
{
  memset(StatFrame,0,sizeof(sStatFrame));  // Reset statistique
  memset(hSrout,0,sizeof(sHistoSrout));
  firstframe = true;
  DaqStarted = true;
  errFirstFrame = false;
}
 
 
void cReadRing::noFile()
{
  if (Dumper) fclose(Dumper);
  if (DumperError) fclose(DumperError);
}
 
void cReadRing::setFile(string *File,bool wr)
/************************************************
 * 
 * 
 ***********************************************/
{
  FileName = *File +  "/MyFile_" + Dev ;
  if (wr) {
    InitDumpFileError();
    InitDumpFile();
  }
}


void cReadRing::setNbSamples(uint16_t nbsamples)
{
  NbSamples = nbsamples;
  log(logINFO,true) << "In cReadRing::setNbSamples(...): NbSamples=" << NbSamples;
}


cReadRing::~cReadRing() 
/************************************************
 * 
 * 
 ***********************************************/
{
  /*	do_shutdown = true;
	sleep(2);
	pfring_shutdown(Ring);
	if (Dumper) pcap_dump_close(Dumper);errFirstFrame
	if (DumperError) pcap_dump_close(DumperError);
  */
    log(logINFO,true) << "Destroy thread " << Dev;
  //	std::terminate();
}

void  cReadRing::setNbEventDisplay(long nb)
{
  NbEventDisplay = nb;
}

bool cReadRing::CreateFifo()
/***********************************************************************************************************************
 * errFirstFrame
 * 
 * ********************************************************************************************************************/
{
	void setNbEventDisplay(long nb);
  string NameFifo = "/var/run/" + Dev + ".fifo";
  if (mkfifo(NameFifo.c_str(),0666) < 0) {
    cout << FgColor::red() << "Error creating : " << NameFifo << "  " << FgColor::white() << endl;
    //return(false);
  }
	
  FdFifo = open(NameFifo.c_str(),O_WRONLY);
  if (!FdFifo) printf("Openning error fifo %s\n",NameFifo.c_str());
  printf("Handle fifo = %s %d\n",NameFifo.c_str(),FdFifo);
  return(true);
}

bool cReadRing::PrintStats(ShmRingBuffer<sStatFrame> *shdnet)
/***********************************************************************************************************************
 * 
 * 
 * ********************************************************************************************************************/
{
  struct timeval endTime;

  gettimeofday(&endTime, NULL);
  pfring_stat pfringStat;
  pfring_stats(Ring,&pfringStat);
  
  StatFrame->deltaMillisec 	= delta_time(&endTime, &startTime);
  StatFrame->delta 				= delta_time(&endTime, &lastTime);
  //	StatFrame->DeviceName		= Dev.c_str();
  StatFrame->DropsPkts			= pfringStat.drop;
  shdnet->push_back(*StatFrame);
  return PrintStats();
}

bool cReadRing::PrintStats()
/***********************************************************************************************************************
 * 
 * 
 * ********************************************************************************************************************/
{
  bool hasPkts = true;
  //if (!DaqStarted) return;
  //cout << "Daq value " << DaqStarted << endl;
  struct timeval endTime;
  std::stringstream sstream; 
  
  double deltaMillisec,delta;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  delta = delta_time(&endTime, &lastTime);
	
  pfring_stat pfringStat;
	
  pfring_stats(Ring,&pfringStat);
	
  //	m.lock();
  //u_int64_t numPkts_temp = StatFrame->NbFrameRec;
  u_int64_t numBytes_temp = StatFrame->NumBytes;
  //	m.unlock();
  //cout << hex <<(u16) StatFrame->MemFeId<< dec << "   -> StatFrame->NbFrameRec = " << StatFrame->NbFrameRec << endl;
  if (StatFrame->NbFrameRec > StatFrame->NbFrameRecPrev) {	
    StatFrame->TrigTimestamp = GetTimeStpThorAsm();
    double rate = (StatFrame->TriggerCount-StatFrame->LastTriggerCount);///((StatFrame->LastTrigTimestamp-StatFrame->TrigTimestamp)*6.666);
    StatFrame->thpt = ((double)8*(numBytes_temp-StatFrame->lastByte))/(delta*1000.0);
    if (rate > 0.0) {
      fprintf(stderr,""
	      "[%s%.2f%s] [%02x] Abs Stats: [%.2f] [%s%s%s][%llu pkts rcvd][%lu pkts dropped]\t"
	      "Total Pkts=%llu/Dropped=%.1f %%\t",
	      FgColor::green(),deltaMillisec/1000,FgColor::white(), 
	      StatFrame->MemFeId,delta,
	      FgColor::green(),Dev.c_str(),FgColor::white(), 
	      StatFrame->NbFrameRec,pfringStat.drop,
	      (StatFrame->NbFrameRec + pfringStat.drop),
	      StatFrame->NbFrameRec == 0 ? 0 : (double)(pfringStat.drop*100)/(double)(StatFrame->NbFrameRec - StatFrame->NbFrameRecPrev + pfringStat.drop));
      fprintf(stderr,
	      " [%.1f pkt/sec - %.2f Mbit/sec] %llu Rate=%5.2f (%d-%d)\n",
	      (double)(StatFrame->NbFrameRec-StatFrame->NbFrameRecPrev),
	      StatFrame->thpt,
	      StatFrame->ErrId,
	      rate,
	      StatFrame->TriggerCountOrig,
	      StatFrame->LastTriggerCountOrig);
    }
    StatFrame->NbFrameRecPrev = StatFrame->NbFrameRec;
    StatFrame->lastByte = numBytes_temp;
    StatFrame->LastTriggerCount = StatFrame->TriggerCount;
    StatFrame->LastTriggerCountOrig = StatFrame->TriggerCountOrig;
    StatFrame->LastTrigTimestamp = StatFrame->TrigTimestamp;
  } else {
    hasPkts = false;
  }
  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
  return hasPkts;
}

void cReadRing::Run() 
/************************************************
 * 
 * 
 ***********************************************/
{
  if(NumCpu > 1) {
    /* Bind this thread to a specific core */
    cpu_set_t cpuset;
    u_long core_id;
    int s;
    if (ThreadsCoreAffinity != -1) {
      core_id = ThreadsCoreAffinity % NumCpu;
    }
    else
      core_id = (Index + 1) % NumCpu;
    
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0)
      fprintf(stderr, "Error while binding thread %s %d to core %ld: errno=%i\n",Dev.c_str(), Index, core_id, s);
    else {
      log(logINFO,true) << "Set thread Interface=" << Dev.c_str() << " " << Index << " on core " << core_id << "/" << NumCpu;
    }
  } // END OF "if(NumCpu > 1)"
  
  log(logINFO,true) << "size share memory " << sizeof(SharedMemory);
  
  while(!do_shutdown) {
    u_char *buffer = NULL;
    struct pfring_pkthdr hdr;
    if(pfring_recv(Ring, &buffer, 0, &hdr, WaitForPacket) > 0) {
      //if ((buffer[12] == 8) && (buffer[13]==0) && (buffer[23] == 17)) {
      //printf("%02x%02x  %02x\n", buffer[12],buffer[13],buffer[23]);
      StatFrame->MemLen = sizeof(S_HeaderFrame)+(NbSamples+2)*2*4+2*2;
      
      Running = true;
      
      struct SharedMemory *TempBuf = (struct SharedMemory *) &buffer[42];
      SetPacket((uint16_t *) &buffer[42],hdr.len);

      StatFrame->NbFrameRec++;
      StatFrame->NumBytes += hdr.len+24 /* 8 Preamble + 4 CRC + 12 IFG (corresponding to IP header) */;
      
      /////////////////////////////////////////////////////////
      // Check header and frame integrity
      bool frameErrornoTT = FrameErrornoTT();
      if (!frameErrornoTT || StatFrame->MemLen != hdr.len-42) {
	if (StatFrame->MemLen != hdr.len-42) {
	  cout << FgColor::red() << "Frame integrity failed:"
	       << " ASM board=0x" << hex<<(int) StatFrame->MemFeId<<dec
	       << ", StatFrame->MemLen (="  << StatFrame->MemLen << ") != hdr.len - 42 (=" << hdr.len - 42 << ")" << FgColor::white() << endl;
	}
	if (!frameErrornoTT) {
	  log(logDEBUG1,true) << FgColor::yellow()
                     << "Header integrity failed:"
                     << " ASM board=0x" << hex<<(int) StatFrame->MemFeId<<dec
                     << ", NbFrameRec=" << StatFrame->NbFrameRec
                     << ", hdr.len=" << hdr.len
                     << ", StatFrame->MemLen=" << StatFrame->MemLen;
	  for (int kk=42;kk<116;kk+=2) {
	    log(logDEBUG2,false) << "  -> buffer[" << kk << "] = " << hex<< (u16) buffer[kk] << (u16) buffer[kk+1];
	    if(kk == 42) {
	      log(logDEBUG2,true) << "  (<- 0x1230 (SoF))";
	    } else if(kk == 48) {
	      log(logDEBUG2,true) << "  (<- 0xFEIdK30)";
	    } else if(kk == 62) {
	      log(logDEBUG2,true) << "  (<- 0xcafe)";
	    } else if(kk == 64) {
	      log(logDEBUG2,true) << "  (<- 0xdeca)";
	    } else if(kk == 66) {
	      log(logDEBUG2,true) << "  (<- 0x0123)";
	    } else if(kk == 68) {
	      log(logDEBUG2,true) << "  (<- 0x4567)";
	    } else if(kk == 70) {
	      log(logDEBUG2,true) << "  (<- 0x89ab)";
	    } else if(kk == 72) {
	      log(logDEBUG2,true) << "  (<- 0xcdef)";
	    } else if(kk == 90) {
	      log(logDEBUG2,true) << "  (<- ThorTT)";
	    } else if(kk == 92) {
	      log(logDEBUG2,true) << "  (<- PatternMsb)";
	    } else if(kk == 94) {
	      log(logDEBUG2,true) << "  (<- PatternOsb)";
	    } else if(kk == 96) {
	      log(logDEBUG2,true) << "  (<- PatternLsb)";
	    } else if(kk == 98) {
	      log(logDEBUG2,true) << "  (<- Oxbobo)";
	    } 
	    //cout << dec << endl;
	  }
	  S_ErrorFrame err = GetErrFrame();
	  log(logDEBUG2,true) << "  -> length fragment = " << hdr.len << "  StatFrame->MemLen = " << StatFrame->MemLen;
	  log(logDEBUG2,true) << "  -> Sof " << err.ErrSoF << " Cafedeca " << err.ErrCafeDeca << " Bobo " << err.ErrBobo << " SOC "
                          << err.ErrSoc << " Crc " << err.ErrCrc << " eof " << err.ErrEoF << " TT " << err.ErrTT << FgColor::white();
	}
      }
      /////////////////////////////////////////////////////////
      /*
      if (StatFrame->NbFrameRec >= 2) {
	return;
	}*/
      
      if (firstframe) {
	StatFrame->MemFeId = GetFeId();
		
	struct S_HeaderFile HdrFile;
	HdrFile.ModeFile = FileMode;
	HdrFile.FrontEndId = GetFeId(); 
	HdrFile.NbSamples  = NbSamples; //GetNbSamples();	
    gettimeofday(&startTime, NULL);
	HdrFile.CreateTime = startTime;

	log(logDEBUG1,true) << FgColor::green()
                        << "Start first frame for ASM board 0x"
                        << hex<<(int) StatFrame->MemFeId<<dec
                        << FgColor::white();
	
	if (frameErrornoTT) {
	  gettimeofday(&startTime, NULL);
	  lastTime = startTime;
	  if (Dumper) fwrite(&HdrFile,sizeof(char),sizeof(HdrFile),Dumper);
	  
	  log(logDEBUG1,true) << FgColor::green()
                          << "  -> Got first frame without error for ASM board 0x"
                          << hex<<(int) StatFrame->MemFeId<<dec
                          << FgColor::white();

	} else if (DumperError) {
	  fwrite(&HdrFile,sizeof(char),sizeof(HdrFile),DumperError);
	}
	firstframe = false;
      } // END OF "if (firstframe)" 
      
      // Compare hdr.len to that of first frame
      if (StatFrame->MemLen > hdr.len-42) StatFrame->UnderSize++;
      if (StatFrame->MemLen < hdr.len-42) StatFrame->OverSize++;
      
      if (frameErrornoTT) {
	//cout << FgColor::green() << "  -> All good, proceed with frame" << FgColor::white() << endl;
	if (StatFrame->MemFeId != GetFeId()) StatFrame->ErrId++;
	StatFrame->NbFrameAmc = GetNbFrameAmc();
	//	  NbSamples = GetNbSamples(); 
	
	// Permet de faire un histo des srout
	//u16 *buf =
	GetChannel(0);
	unsigned short Ch = GetCh();
	if (Ch < 24) {
	  hSrout->noBoard = GetFeId();
	  hSrout->nohalfDrs = Ch /4;
	  hSrout->HistoSrout[hSrout->nohalfDrs][GetSrout()]++;
	}
	
	StatFrame->NumFrameOk++;
	if (IsErrorTT()) {
	  //if (StatFrame->MemFeId == 0x1b) 
	  //cout << hex<<(u16) StatFrame->MemFeId<<dec << "  " << GetNbFrameAsm() << "  " << StatFrame->NbFrameRec << " -> Pattern : " << hex<<GetPattern()<<dec << endl;
	  TriggerCount = GetCptTriggerAsm();
	  StatFrame->TriggerCountOrig = false;
	  StatFrame->NumTriggerCountsFromASM++;
	}
	else {
	  TriggerCount = GetCptTriggerThor();
	  StatFrame->TriggerCountOrig = true;
      if (eventBuilder) pEventBuilder->setEvent(TriggerCount,GetPattern(),StatFrame->MemLen,&buffer[42],GetTimeStpThorAsm());
	}
	
	StatFrame->NbFrameAsm= GetNbFrameAsm();
	StatFrame->NbFrameAsmLost += StatFrame->NbFrameAsm - (StatFrame->NbFrameAsmOld+1);
	StatFrame->NbFrameAsmOld  = StatFrame->NbFrameAsm;
	StatFrame->TriggerCount = TriggerCount;
	if ((Dumper) && (!eventBuilder)) {
	  switch (FileMode) {
	  case HEADER 	:fwrite(&buffer[42],sizeof(char),(sizeof(struct S_HeaderFrame)),Dumper);break;
	  case RAWDATA	:fwrite(&buffer[42],sizeof(char),(hdr.len-42),Dumper);break; 
	  case ALL		:fwrite(&buffer[0],sizeof(char),(hdr.len),Dumper);break; 
	  }
	}

	if ((((TriggerCount) % NbEventDisplay) == 0) && !eventBuilder) {
	  //					printf("Write shm\n");
        ShdMem->push_back(*TempBuf);
	  //					ShdSrout->push_back(*hSrout);
	}
      }	else if (DumperError) {  
        switch (FileMode) {
            case HEADER 	:fwrite(&buffer[42],sizeof(char),(sizeof(struct S_HeaderFrame)),DumperError);break;
            case RAWDATA	:fwrite(&buffer[42],sizeof(char),(hdr.len-42),DumperError);break; 
            case ALL	:fwrite(&buffer[0],sizeof(char),(hdr.len),DumperError);break; 
        }
      }
    } else {
      if(WaitForPacket == 0)  {
	usleep(1); //sched_yield();
	fflush(Dumper);
      }
    }
  }
  
  if (Dumper) fclose(Dumper);
  if (DumperError) fclose(DumperError);
}

void cReadRing::Stop() 
/************************************************
 * 
 * 
 ***********************************************/
{
  do_shutdown = true;
  //sleep(2);
  pfring_shutdown(Ring);
  close(FdFifo);
  free(StatFrame);
  free(hSrout);
  //remove(&NameFifo[0]);
}

bool cReadRing::InitDumpFileError()
/***********************************************************************
 * 
 * 
 **********************************************************************/
{
  string NameFile = FileName + ".err";
  DumperError = fopen(NameFile.c_str(),"wb");
  if(DumperError == NULL) {
    log(logERROR,true) << "Unable to open dump error file " << NameFile.c_str();
    return(false);
  }	
  return(true);
}

bool cReadRing::InitDumpFile(const bool rollover)
/***********************************************************************
 * 
 * 
 **********************************************************************/
{
  if (Dumper) fclose(Dumper);
  std::string NameFile;
  if (rollover) NameFile = FileName + "_" + std::to_string(Cptfile++) + ".bin";
  else NameFile = FileName + "_" + std::to_string(Cptfile) + ".bin";
  //	if (!Compress) Dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 9000 /* MTU */), NameFile.c_str());
  Dumper = fopen(NameFile.c_str(),"wb");
	
  if(Dumper == NULL) {
    log(logERROR,true) << "Unable to open dump file " <<  NameFile.c_str();
    return(-1);
    return(false);
  }
  else log(logINFO,true) << "Creating file " << NameFile.c_str();
  return(true);
} 
