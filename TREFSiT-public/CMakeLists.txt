cmake_minimum_required(VERSION 3.5)

project(tor_project)

# Create a sources variable with a link to all cpp files to compile
set (tor_video_sou
    src/tor_video/main_tor_video.cpp
    src/tor_video/torv_flow.cpp
)

# Add an executable with the above sources
add_executable(tor_video ${tor_video_sou})
target_include_directories(tor_video PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(tor_video 
        ${PROJECT_SOURCE_DIR}/lib/win/liblibconfig++.dll.a
        ${PROJECT_SOURCE_DIR}/lib/win/lib_TLS2_SE.a 
        ${PROJECT_SOURCE_DIR}/lib/win/libFlow2SE.a 
        ${PROJECT_SOURCE_DIR}/lib/win/libPcapSE.a
        ${PROJECT_SOURCE_DIR}/lib/win/libPacketSE.a 
        ${PROJECT_SOURCE_DIR}/lib/win/libHashSE.a )

