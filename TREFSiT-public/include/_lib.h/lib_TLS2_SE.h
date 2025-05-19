#ifndef LIB_TLS2_SE_H
#define LIB_TLS2_SE_H

#include <cstdlib>
#include <cstring>
#include <stdint.h> 
#include <vector>
#include "libPacketSE.h"

struct stt_TLS_record
{
    uint32_t pck_no;
    timeVS tm_pck;
    uint32_t len_TLS;
    uint8_t content_type;
    uint8_t get_type;
    uint8_t b_sc;
};

struct stt_HTTP_ADU
{
    //request
    uint32_t pkn_requ;
    timeVS tm_requ;
    uint32_t num_TLS_requ;
    uint32_t len_TLS_requ;
    //response
    uint32_t pkn_resp;
    timeVS tm_resp_b;
    timeVS tm_resp_e;
    uint32_t num_TLS_resp;
    uint32_t len_TLS_resp;
    uint32_t len_estimate1;
    uint32_t len_estimate2;
    //resp vector
    std::vector<uint32_t> vct_requ_len;
    std::vector<uint32_t> vct_TLS_datalen;
};

class I_TLS_flow
{
public:
    virtual ~I_TLS_flow() {}
public:
    /**
     * @brief 设置 flow base SEQ
     * 
     * @param CPacket* point of packet
     * @param b_srv packet from server or client
    */
    virtual void set_base_seq(CPacket* lp_pck, bool b_srv) = 0;

    /**
     * @brief 设置 flow base SEQ
     * 
     * @param seq_c base SEQ of client
     * @param seq_s base SEQ of server
     */
    virtual void set_base_seq(uint32_t seq_c, uint32_t seq_s) = 0;

    /**
     * @brief Set the length threshold for client request
     * 
     * @param len length
     */
    virtual void set_client_requ_thre(int len) = 0;

    /**
     * @brief 计算当前包，两个方向偏移值
     * 
     * @param lp_pck 当前包
     * @param b_srv 是否是server数据包
     * @param c_off 返回client offset
     * @param s_off 返回server offset
     */
    virtual void calc_seq(CPacket* lp_pck, bool b_srv, int& c_off, int& s_off) = 0;

    /**
     * @brief 把 Packet Payload 放入 flow 中处理
     * 
     * @param lp_pck packet 指针
     * @param b_srv 是否服务器数据
     * @param b_ADU 返回是否ADU完成
     * @return int 成果否
     */
    virtual int TLS_flow_packet(CPacket* lp_pck, bool b_srv, bool& b_ADU) = 0;

    /**
     * @brief 在client到达新的确认包时，检查server端的数据完整性。
     * 
     * @param lp_pck packet
     * @return bool 
     */
    virtual bool check_TLS_ACK_over(CPacket* lp_pck) = 0;
    virtual bool check_server_TLS_end() = 0;

    /**
     * @brief get TLS version
    */
    virtual int get_TLS_version() = 0;

    /**
     * @brief 是否是HTTP 2
     * 
     * @return bool
     */
    virtual bool is_http2() = 0;

    /**
     * @brief TLS records 集合
    */
    virtual std::vector<stt_TLS_record> *get_TLS_vector() = 0;
    virtual std::vector<stt_TLS_record> *get_dire_TLS_vct() = 0;

    /**
     * @brief HTTP ADU 集合
    */
    virtual std::vector<stt_HTTP_ADU> *get_ADU_vector(int min_requ) = 0;

    /**
     * @brief current ADU TLS record, request 以负值出现
     */
    virtual std::vector<int> *get_cur_ADU() = 0;

    /**
     * @brief Current TLS object
     */
    virtual std::vector<int> *get_Current_TLS() = 0;
};

class I_memory_manager
{
public:
    virtual ~I_memory_manager() {}
public:
    virtual uint8_t *lock_memory_cell(int type, uint32_t& id, uint32_t& len) = 0;
    virtual bool unlock_memory_cell(int type, uint32_t id) = 0;
};

/**
 * TLS总盘
*/
class I_TLS_flow_stat
{
public:
    virtual ~I_TLS_flow_stat() {}
public:
    /**
     * @brief Create a TLS flow object
     * 
     * @param server_level  1 --- 大内存， 2 --- 小内存
     * @param client_level 
     * @return I_TLS_flow* 
     */
    virtual I_TLS_flow *create_TLS_flow(int server_level, int client_level) = 0;

    virtual bool check_stat_buffer() = 0; 
    virtual I_memory_manager* get_MM() = 0;
};

class TLS_flow_stat_creator
{
public:
    static I_TLS_flow_stat* create_TLS_flow_stat();     
};
#endif
