#ifndef INTERFACE_REALTIME_H
#define INTERFACE_REALTIME_H

#include <stdint.h> 
#include <vector>
#include <string>

struct tm_info
{
    uint32_t            tv_sec;
    uint32_t            tv_usec;
};

struct info_server
{
    std::string str_IP;
    uint16_t port;
    std::string str_SNI;
    tm_info time;
    int end_type;
};

class INF_realtime_sys
{
public:
    virtual ~INF_realtime_sys(){}
public:
    virtual bool init_load() = 0;
    virtual void rt_single_seg(info_server stt_svr, std::vector<int> *lp_vct_len) = 0;
    virtual void rt_multi_seg(info_server stt_svr, std::vector<int> *lp_vct_len) = 0;
};

#endif
