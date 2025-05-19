#ifndef LINUX_YOUTUBE_H
#define LINUX_YOUTUBE_H

#include "_lib.h/lib_TLS2_SE.h"
#include "_base_tools/std_flow2_TLS.h"
#include <vector>

struct stt_tor_ADU
{
    timeVS tm_requ;
    uint32_t pkn_requ;
    uint32_t len_requ;
    uint32_t num_tls_requ;
    timeVS tm_resp;
    uint32_t pkn_resp;
    uint32_t len_resp;
    uint32_t num_tls_resp;

    std::vector<uint32_t> vct_c_rec;
    std::vector<uint32_t> vct_s_rec;
};

class tor_flow;

class tor_flow_creator: public IFlow2ObjectCreator
{
public:
    tor_flow_creator(packet_statistics_object_type type, std::string fname,
                    I_TLS_flow_stat* lp_stat, std::string filter, int min, bool b_save);
    ~tor_flow_creator();
public:
    IFlow2Object* create_Object(uint8_t* buf, int len);
public:
    bool isSave() {return b_csv_save;}
    packet_statistics_object_type getStatType() {return pso_type;}

    I_TLS_flow_stat* get_TLS_stat() {return lp_TLS_stat;} 
    int get_threshold() {return pck_threshold;}
    std::string get_filter() {return str_filter;}

    std::string getName() {return strName;}
    std::string get_path() {return str_path;}
    std::string get_name_ADU() {return str_adu;}
    int get_num_tor() {return num_tor_flow;}

    void record_Tor_flow(tor_flow *lp_tor) {vct_tor_flow.push_back(lp_tor);}

    void set_thresholds(int th_1, int th_2, int th_3, int th_4){
        thre_ADU_RTT = (double)th_1/1000;
        thre_end_rest = th_2;
        thre_ADU_requ_intv = (double)th_3/1000;
        thre_ADU_min = th_4;
    }

    void add_TLS_stat(uint32_t len){
        if(len>0 && len<max_tls)
            len_stat[len] ++;
    }

    bool save_TLS_state(){
        bool bout = false;
        FILE *fp = fopen(str_TLS_stat.c_str(), "wt");
        if(fp)
        {
            fprintf(fp, "len,rate\n");
            int sum = 0;
            for(int i = 1; i < 5000; i++)
                sum += len_stat[i];
            int max = sum;
            for(int idx = 0; idx < 20; idx++)
            {
                int cur = 0, len;
                for(int i = 1; i < 5000; i++)
                {
                    if(cur < len_stat[i] && len_stat[i] < max)
                    {
                        cur = len_stat[i];
                        len = i;
                    }
                }
                max = cur;
                fprintf(fp, "%d,%f\n", len, (double)cur/sum);
            }
            fclose(fp);
            bout = true;
        }
        else
            std::cout << "file open error! " << str_TLS_stat << std::endl;
        return bout;
    }
public:
    void add_tor_flow(std::vector<stt_TLS_record> *lp_rec);
    bool save_ADU(std::string fn);
    void check_Tor_server_TLS(uint32_t pkn);
    //bool save_competition_msg(int len_seg, std::vector<uint32_t> *vct_sub, int type);
private:
    bool open_csv(std::string str_name);
    int calc_threshold(std::vector<uint32_t> *lp_vct_rec, int thre, int type, int &num);
private:
    int check_len(int len, int type){
        int iout = 0;
        if(type == 0)
        {
            if(len%514 == 0)
            {}
            else if(len%64==0)// && len<=128)
            {}
            else
            {
                int m_len = len;
                while(m_len > 514)
                    m_len -= 514;
                if(m_len%64==0)// && len<=128)
                {}else
                    iout = len;
            }
        }
        else
        {
            if(len % 514 != 0)
            {
                int m_len = len;
                while(m_len > 514)
                    m_len -= 514;
                if(m_len % 64 == 0)
                    iout = m_len;
                else
                    iout = len;
            }
        }
        return iout;
    }

    bool find_pkn(uint32_t pkn)
    {
        bool bfind = false;
        for(std::vector<uint32_t>::iterator iter=vct_request_pck.begin(); iter!=vct_request_pck.end(); ++iter)
        {
            if(pkn == *iter)
            {
                bfind = true;
                break;
            }
            if(*iter > pkn)
                break;
        }
        return bfind;
    }
    double diff_time(timeVS tm_b, timeVS tm_e)
    {
        double db_out = 0;
        if(tm_b.tv_usec > tm_e.tv_usec)
            db_out = (double)tm_e.tv_sec - tm_b.tv_sec - 1 + (double)(1000000 + tm_e.tv_usec - tm_b.tv_usec)/1000000;
        else 
            db_out = (double)tm_e.tv_sec - tm_b.tv_sec + (double)(tm_e.tv_usec - tm_b.tv_usec)/1000000;
        return db_out;
    }
private:
    packet_statistics_object_type pso_type;
    I_TLS_flow_stat* lp_TLS_stat;
    std::string strName, str_path, str_adu, str_pcap, str_TLS_stat, str_comb;
    std::string str_filter;
private:
    int pck_threshold;
    bool b_csv_save;
    std::vector<stt_TLS_record> vct_tor_1, vct_tor_all;
    int num_tor_flow;
private:
    void arrange_tor_adu();
    std::vector<stt_tor_ADU> vct_tor_ADU;
    std::vector<tor_flow*> vct_tor_flow;
    std::vector<uint32_t> vct_request_pck;
private:
    static const int max_tls = 16500;
    uint32_t len_stat[max_tls];
private:
    double thre_ADU_RTT;
    double thre_ADU_requ_intv;
    double thre_end_rest;
    int thre_ADU_min;
};

//==============================================================================
//==============================================================================
//==============================================================================

class tor_flow: public flow2_TLS
{
public:
    tor_flow(uint8_t* buf, int len, tor_flow_creator* lpFOC);
    ~tor_flow();
public:
    bool addPacket(CPacket* lppck, bool bSou);
    bool saveObject(FILE* fp, uint64_t cntP, bool bFin);
public:
    bool check_srv_TLS_end(){
        if(lp_TLS_flow)
            return lp_TLS_flow->check_server_TLS_end();
        else
            return false;
    }
protected:    //TLS2
    void create_TLS_stat(CPacket* lppck, bool bSrv){    
        I_TLS_flow_stat *lp_stat = lpCreator->get_TLS_stat();
        if(lp_stat){
            lp_TLS_flow = lp_stat->create_TLS_flow(1, 0);
            if(lp_TLS_flow)
            {
                lp_TLS_flow->set_base_seq(lppck, bSrv);
                //request threshold
                lp_TLS_flow->set_client_requ_thre(300);
            }
        }
    }
private:
    bool check_tor_flow(std::vector<stt_TLS_record> *lp_rec);
private:
    tor_flow_creator* lpCreator;
    I_TLS_flow *lp_TLS_flow;
private:
    bool ch_checked;
    uint64_t len_cs, len_sc;
};

#endif
