cmake_minimum_required(VERSION 2.8)
#Déclaration du projet

project(DaqDpga)

set (O_FLAG "-O2 -DHAVE_PF_RING")
set (CFLAGS "${O_FLAG} -Wall -D ENABLE_BPF") 
#-D HAVE_PF_RING_ZC")
set (CMAKE_CXX_FLAGS "-std=c++11 ${CFLAGS} -Wextra -Wno-unused-parameter -ggdb -g -pthread")
#set (EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/build/bin)
#set (Libraries "pfring pthread")



#set (USERLIB tinyxml)

include_directories(./include/ ../include  ${LIB_SHM_PATH}/include  ${LIB_DECODEFRAME_PATH}/include /usr/local/include)

#link_directories(/usr/local/lib ../../lib/build)

#Configuration de l'édition de liens

#add_library(libpthread STATIC IMPORTED)
#add_library(libpfring STATIC IMPORTED)
#add_library(libbsd STATIC IMPORTED)
#add_library(libz STATIC IMPORTED)
#add_library(librt STATIC IMPORTED)
#add_library(libringshm SHARED IMPORTED)

file (
		GLOB_RECURSE

	source_files
	src/*.c
	src/*.cpp
        
	include/*.h     
	../include/*.h
)

#Déclaration de l'exécutable

add_executable(

        daqdpga
        ${source_files}

)

target_link_libraries(daqdpga PUBLIC pthread pfring pcap z rt ringshm frame)

#add_executable(some_executable some_executable_source.c)
#add_custom_target(daqdpga DEPENDS ${source_files})
