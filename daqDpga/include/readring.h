#ifndef READRING_H
#define READRING_H
#include <thread>
#include <netinet/in.h>
#include <semaphore.h>
#include <mutex>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include "frame.h"
#include "GenericTypeDefs.h"
#include <pfring.h>
#include "ringshm.h"
#include "shdmem.h" // contains sStatFrame struct
#include "decodeframe.h"




class cReadRing : public DecodeFrame 
{

	public:
		cReadRing(int index,std::string dev,int caplen,u_int32_t flags,int threads_core_affinity,std::string *File,ShmRingBuffer<SharedMemory> *shdmem,
					ShmRingBuffer<sHistoSrout> *shdsrout,bool dumpfile,packet_direction direction,int verbose,int wait_for_packet,unsigned int numcpu);
		~cReadRing(); 

		void Stop();
//		void SendPauseDaq();
		struct sStatFrame *GetStats() {return StatFrame;};
		void PrintStats();
		void PrintStats(ShmRingBuffer<sStatFrame> *shdnet);
		std::string GetDev() {return Dev;};
		u_int GetIndex() {return Index;};
		void SetOnlyHeader(eModefile filemode) {FileMode = filemode;};
		void SetCompress(bool compress) {Compress = compress;};
		std::thread MemberThread() {return std::thread([=] { Run(); });}
		bool GetRunning () {return (Running);};
		bool GetStarted () {return (DaqStarted);};
		u32 GetTriggerCount() {return TriggerCount;};
		bool InitDumpFile(const bool rollover=false);
		bool CreateFifo();
		void setNbEventDisplay(long nb);
		void StartDaq();
		void setFile(string *File,bool wr);
		void noFile();
		
	protected:
	
	private:
		std::thread the_thread;
		void Run();
		
		bool InitDumpFileError();
		void Decodepacket(const struct pfring_pkthdr *h, const u_char *p,bool first,bool *frameok);
		const unsigned char BufferStart[2] 	= {0xaa,0xdc};
		const unsigned char BufferStop[2] 	= {0xaa,0xcd};
		std::string filter_buffer = "src 192.168.2.129 and  udp port 60000";
		unsigned int NumCpu;
		bool Compress=false; 
		u32 TriggerCount;
		bool do_shutdown=false;
		bool WaitForPacket;
		bool Running;
		bool DumpFile;
		pfring_stat pfringStat;
		struct sStatFrame *StatFrame; 
		ShmRingBuffer<SharedMemory> *ShdMem;

		struct timeval startTime;
		struct timeval lastTime;
		std::mutex m;
		int FdFifo;
		int NbEventDisplay;
		int Index;
		std::string Dev;
		pfring *Ring;
		int Verbose;
		packet_direction Direction;

		int ThreadsCoreAffinity;
		int32_t thiszone;
		std::string FileName;
		int Cptfile;
		eModefile FileMode;
		FILE *Dumper = NULL;
		FILE *DumperError = NULL;
		uint16_t NbSamples;
//		u_int64_t numPkts;
//		u_int64_t numBytes;
		u_int64_t lastPkts;
		u_int64_t lastByte;
		bool 	firstframe;
		bool DaqStarted;
		sHistoSrout *hSrout;
		ShmRingBuffer<sHistoSrout> *ShdSrout;
        bool errFirstFrame;
};
#endif
