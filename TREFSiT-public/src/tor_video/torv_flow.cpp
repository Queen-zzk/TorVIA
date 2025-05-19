#include <iostream>
#include <algorithm>

#include "tor_video/torv_flow.h"

using namespace std;

const uint32_t frequ_c_len = 514;
const uint32_t frequ_max_len = 4048;
const double tm_intv_rr = 0.2;
const uint32_t torv_flow_check_pkn = 100;
const int check_443_TLS_num = 16;
const int frequ_tor_TLS = 9;
const int tor_frequ_TLS_len[frequ_tor_TLS] = {4048, 514, 3598, 64, 578, 3662, 1028, 256, 3792};

tor_flow_creator::tor_flow_creator(packet_statistics_object_type type, string fname,
                                     I_TLS_flow_stat* lp_stat, string filter, int min, bool b_save)
{
    pso_type = type;
    lp_TLS_stat = lp_stat;
    str_filter = filter;
    pck_threshold = min;
    b_csv_save = b_save;

    //str_path = fpath;
    str_pcap = fname;
    strName = fname + ".TLS.record.csv";
    open_csv(strName);

    str_adu = fname + ".Tor.ADU.csv";
    str_TLS_stat = fname + ".len.TLS.stat.csv";
    str_comb = fname + ".comb.TLS.csv";
//    num_file_sub = num_file_seg = 0;
    num_tor_flow = 0;
    vct_tor_1.clear();
    vct_tor_all.clear();

    for(int i=0; i<max_tls; i++)
        len_stat[i] = 0;
}

tor_flow_creator::~tor_flow_creator()
{

}

IFlow2Object* tor_flow_creator::create_Object(uint8_t* buf, int len)
{
    tor_flow* lpf = new tor_flow(buf, len, this);
    return lpf;
}

bool tor_flow_creator::open_csv(std::string str_name)
{
    bool bout = false;
    FILE* fp = fopen(str_name.c_str(), "wt");
    if(fp)
    {
        fclose(fp);
        bout = true;
    }
    else
        cout << "open file error, file:" << str_name << endl;
    
    return bout;
}

void tor_flow_creator::add_tor_flow(vector<stt_TLS_record> *lp_rec)
{
    if(num_tor_flow == 0)
    {
        for(vector<stt_TLS_record>::iterator iter=lp_rec->begin(); iter!=lp_rec->end(); ++iter)
            if((*iter).content_type==23)
            {
                (*iter).get_type = 1;
                vct_tor_all.push_back(*iter);
            }
    }
    else if(num_tor_flow == 1)
    {
        for(vector<stt_TLS_record>::iterator iter=vct_tor_all.begin(); iter!=vct_tor_all.end(); ++iter)
            vct_tor_1.push_back(*iter);
        vct_tor_all.clear();

        vector<stt_TLS_record>::iterator iter_1 = lp_rec->begin();
        vector<stt_TLS_record>::iterator iter_2 = vct_tor_1.begin();
        while(iter_1 != lp_rec->end() || iter_2 != vct_tor_1.end())
        {
            while((*iter_1).content_type!=23 && iter_1 != lp_rec->end())
                ++iter_1;
            if(iter_1 == lp_rec->end() && iter_2 != vct_tor_1.end())
            {
                (*iter_2).get_type = 2;
                vct_tor_all.push_back(*iter_2);
                ++iter_2;
            }
            else if(iter_2 == vct_tor_1.end() && iter_1 != lp_rec->end())
            {
                (*iter_1).get_type = 1;
                vct_tor_all.push_back(*iter_1);
                ++iter_1;
            }
            else if(iter_1 != lp_rec->end() && iter_2 != vct_tor_1.end())
            {
                if((*iter_1).pck_no > (*iter_2).pck_no)
                {
                    (*iter_2).get_type = 2;
                    vct_tor_all.push_back(*iter_2);
                    ++iter_2;
                }
                else
                {
                    (*iter_1).get_type = 1;
                    vct_tor_all.push_back(*iter_1);
                    ++iter_1;
                }
            }
        }
    }
    num_tor_flow ++;
}

bool tor_flow_creator::save_ADU(string fname)
{
    bool bout = false;
    if(num_tor_flow > 2)
    {
        cout << "more than 2 tor flows found" << endl;
        return bout;
    }
    else
    {
        for(vector<stt_TLS_record>::iterator iter=vct_tor_all.begin(); iter!=vct_tor_all.end(); ++iter)
        {
            if(!(*iter).b_sc)
            {
                if(find_pkn((*iter).pck_no))
                    (*iter).get_type += 4;
            }
        }
    }

    FILE* fp_comb = fopen(str_comb.c_str(), "wt");
    if(fp_comb)
    {
        fprintf(fp_comb, "pkn,time,c_len,s_len,from\n");
        for(vector<stt_TLS_record>::iterator iter=vct_tor_all.begin(); iter!=vct_tor_all.end(); ++iter)
        {
            if(!(*iter).b_sc)
                fprintf(fp_comb, "%u,%d.%06d,%d,,%d\n", 
                            (*iter).pck_no, (*iter).tm_pck.tv_sec, (*iter).tm_pck.tv_usec, 
                            (*iter).len_TLS, (*iter).get_type);
            else
                fprintf(fp_comb, "%u,%d.%06d,,%d,%d\n", 
                            (*iter).pck_no, (*iter).tm_pck.tv_sec, (*iter).tm_pck.tv_usec, 
                            (*iter).len_TLS, (*iter).get_type);
        }

        fclose(fp_comb);
    }
    else
        cout << str_comb << " error open!" << endl;

    arrange_tor_adu();

    vector<uint32_t> vct_rev_adu;
    FILE* fp = fopen(str_adu.c_str(), "wt");
    if(fp)
    {
        fprintf(fp, "tm_c,pkn_c,num_tls_c,len_c,tm_s,pkn_s,num_tls_s,len_s,tm_diff,tm_ADU,,...\n");
        double tm_diff_adu = 0;
        bool b_find_last = false;
        timeVS last_requ;
        int seg = 0;
        for(vector<stt_tor_ADU>::iterator iter=vct_tor_ADU.begin(); iter!=vct_tor_ADU.end(); ++iter)
        {
            if((*iter).len_resp > 4000)
            {
                char buf_tmc[50], buf_tms[50];
                sprintf(buf_tmc, "%d.%06d", (*iter).tm_requ.tv_sec, (*iter).tm_requ.tv_usec);
                
                sprintf(buf_tms, "%d.%06d", (*iter).tm_resp.tv_sec, (*iter).tm_resp.tv_usec);
                double tm_diff = diff_time((*iter).tm_requ, (*iter).tm_resp);
                if(seg > 0)
                {
                    tm_diff_adu = diff_time(last_requ, (*iter).tm_requ);
                    if(tm_diff_adu > thre_end_rest)
                        b_find_last = true;
                }
                seg++;
                last_requ = (*iter).tm_requ;

                fprintf(fp,"%s,%u,%u,%u,%s,%u,%u,%u,%f,%f,,", 
                        buf_tmc, (*iter).pkn_requ, (*iter).num_tls_requ, (*iter).len_requ,
                        buf_tms, (*iter).pkn_resp, (*iter).num_tls_resp, (*iter).len_resp,
                        tm_diff, tm_diff_adu);
                if(!b_find_last)
                    vct_rev_adu.push_back((*iter).len_resp);
                int num, len;
                //if((*iter).len_resp == 680536)
                //    int wos = 1; //debug
                /*
                len = calc_threshold(&((*iter).vct_s_rec), 1156, 0, num);
                fprintf(fp, "1156,%d,%d,,", num, len);
                len = calc_threshold(&((*iter).vct_s_rec), 1670, 0, num);
                fprintf(fp, "1670,%d,%d,,", num, len);
                len = calc_threshold(&((*iter).vct_s_rec), 1028, 0, num);
                fprintf(fp, "1028,%d,%d,,", num, len);

                for(vector<uint32_t>::iterator iter_tls=(*iter).vct_c_rec.begin(); iter_tls!=(*iter).vct_c_rec.end(); ++iter_tls)
                    fprintf(fp, "%u,", *iter_tls);
                fprintf(fp, "|,");
                */
                for(vector<uint32_t>::iterator iter_tls=(*iter).vct_s_rec.begin(); iter_tls!=(*iter).vct_s_rec.end(); ++iter_tls)
                    fprintf(fp, "%u,", *iter_tls);
                fprintf(fp, "\n");
            }
        }
        fclose(fp);
    }

    fp = fopen(fname.c_str(), "at");
    if(fp)
    {
        fprintf(fp, "%s,,", str_pcap.c_str());
        for (vector<uint32_t>::reverse_iterator it = vct_rev_adu.rbegin(); it != vct_rev_adu.rend(); it++)
            fprintf(fp, "%u,", *it);
        fprintf(fp, "\n");
        fclose(fp);
    }

    return bout;
}

int tor_flow_creator::calc_threshold(vector<uint32_t> *lp_vct_rec, int thre, int type, int &num)
{
    int iout = 0;
    num = 0;

    for(vector<uint32_t>::iterator iter=lp_vct_rec->begin(); iter!=lp_vct_rec->end(); ++iter)
    {
        if((*iter) <= thre)
        {
            if(check_len(*iter, type) > 0)
            {
                num ++;
                iout += *iter;
            }
        }    
        else
        {
            num ++;
            iout += (*iter);
        }
    }
    return iout;
}

void tor_flow_creator::arrange_tor_adu()
{
    stt_tor_ADU st_adu;
    int i_state = 0;

    for(vector<stt_TLS_record>::iterator iter=vct_tor_all.begin(); iter!=vct_tor_all.end(); ++iter)
    {
        if(!(*iter).b_sc)   //client
        {
            if((*iter).get_type >= 4) //2 flow TLS record end
            {
                if(i_state == 0 || i_state == 2)
                {
                    for(vector<stt_TLS_record>::iterator iter_new = iter + 1; iter_new!=vct_tor_all.end(); ++iter_new)
                    {
                        if((*iter_new).b_sc)
                        {
//                            if((*iter).pck_no == 43097)
//                                int wos = 1;  //debug
                            double tm_RTT = diff_time((*iter).tm_pck, (*iter_new).tm_pck);
                            double tm_requ_intv;
                            if(i_state == 2)
                                tm_requ_intv = diff_time(st_adu.tm_requ, (*iter).tm_pck);

                            if(tm_RTT > thre_ADU_RTT 
                                && ((i_state == 2 && tm_requ_intv > thre_ADU_requ_intv) || i_state == 0))
                            {
                                if(i_state == 2 && st_adu.len_resp > thre_ADU_min)
                                    vct_tor_ADU.push_back(st_adu);
                                {
                                    memset(&st_adu, 0, sizeof(stt_tor_ADU));
                                    st_adu.tm_requ = (*iter).tm_pck;
                                    st_adu.len_requ += (*iter).len_TLS;
                                    st_adu.num_tls_requ ++;
                                    st_adu.pkn_requ = (*iter).pck_no;
                                    st_adu.vct_c_rec.push_back((*iter).len_TLS);
                                    i_state = 1;
                                }
                            }
                            break;
                        }
                    }
                }
                else if(i_state == 1)
                {
                    st_adu.len_requ += (*iter).len_TLS;
                    st_adu.num_tls_requ ++;
                    st_adu.vct_c_rec.push_back((*iter).len_TLS);
                }
            }
        }
        else                //server
        {
            if(i_state == 1 || i_state == 2)
            {
                i_state = 2;
                if(st_adu.len_resp == 0)
                {
                    st_adu.tm_resp = (*iter).tm_pck;
                    st_adu.pkn_resp = (*iter).pck_no;
                }
                st_adu.len_resp += (*iter).len_TLS;
                st_adu.num_tls_resp ++;
                st_adu.vct_s_rec.push_back((*iter).len_TLS);
            }
        }
    }
    if(st_adu.len_requ > 0 && st_adu.len_resp > 0 && i_state <= 2)
        vct_tor_ADU.push_back(st_adu);
}

void tor_flow_creator::check_Tor_server_TLS(uint32_t pkn)
{
    int num_flow = 0, num_TLS_end = 0;
    for(vector<tor_flow*>::iterator iter=vct_tor_flow.begin(); iter!=vct_tor_flow.end(); ++iter)
    {
        if((*iter)->getPckCnt() > 100)
        {
            num_flow++;
            if((*iter)->check_srv_TLS_end())
                num_TLS_end ++;
        }
    }
    if(num_flow <= 2 && num_TLS_end == num_flow)
    {
        vct_request_pck.push_back(pkn);
    }
}

//===============================================================================
//===============================================================================
//===============================================================================
//===============================================================================

tor_flow::tor_flow(uint8_t* buf, int len, tor_flow_creator* lpFOC)
    :flow2_TLS(buf, len)
{
    lpCreator = lpFOC;

    lp_TLS_flow = NULL;

    len_cs = len_sc = 0;
    ch_checked = false;
}

tor_flow::~tor_flow()
{
    if(lp_TLS_flow)
        delete lp_TLS_flow;
}

bool tor_flow::addPacket(CPacket* lppck, bool bSou)
{
    bool bout = false;

    if(lppck)
    {
        bout = true;
        if(lppck->getPckNum() == 3219)
            int ows = 1; //debug
        if(i_TLS_state < 2 && bSou)
        {
            //通过CH的SNI对TLS flow进行处理
            if(getPckCnt() <= 2)
            {
                check_TLS_CH(lppck, lpCreator->get_filter());
                if(i_TLS_state == 2)
                {
                    if(!str_SNI.empty())
                    {
                        if(lppck->getDstPort() != 443)
                        {
                            ch_checked = true;
                            lpCreator->record_Tor_flow(this);
                        }
                        else
                            i_TLS_state = 5;
                    }
                    else
                    {
                        if(lppck->getDstPort() == 443)
                            i_TLS_state = 5;
                        else if(lppck->getSrcPort() == 443)
                            i_TLS_state = 3;
                    }
                }
            }
            //通过tls content type判断
/*            
            if(lpCreator->get_filter().empty() && i_TLS_state == 0)
            {
                if(getPckCnt() < torv_flow_check_pkn)
                {
                    check_TLS_record_head(lppck, !bSou);
                    if(i_TLS_state == 2)
                    {
                        if(lppck->getDstPort() == 443)
                            i_TLS_state = 5;
                        else if(lppck->getSrcPort() == 443)
                            i_TLS_state = 3;
                    }
                }
                else
                    i_TLS_state = 3;
            }
*/            
        }

        //选中的TLS flow进行数据处理
        if(i_TLS_state == 2 || i_TLS_state == 1)
        {
            if(bSou)
                len_cs += lppck->getLenPayload();
            else
                len_sc += lppck->getLenPayload();
            if(lp_TLS_flow)
            {
                bool b_adu;
                int ret = lp_TLS_flow->TLS_flow_packet(lppck, !bSou, b_adu);
                if(ret<0)
                    i_TLS_state = 4;
                else if(ret > 0)
                {
                    if(bSou)    //client
                        lpCreator->check_Tor_server_TLS(lppck->getPckNum());
                }
            }
        }
        else if(i_TLS_state == 5)    //port 443
        {
            if(lp_TLS_flow)
            {
                bool b_adu;
                int ret = lp_TLS_flow->TLS_flow_packet(lppck, !bSou, b_adu);
                if(ret<0)
                    i_TLS_state = 4;
                
                vector<stt_TLS_record> *lp_records = lp_TLS_flow->get_TLS_vector();
                if(lp_records->size() >= check_443_TLS_num)
                {
                    int num = 0;
                    for(vector<stt_TLS_record>::iterator iter=lp_records->begin(); iter!=lp_records->end(); ++iter)
                    {
                        if((*iter).content_type==23)
                        {
                            int len = (*iter).len_TLS-22;
                            for(int i=0; i < frequ_tor_TLS; i++)
                            {
                                if(len == tor_frequ_TLS_len[i])
                                {
                                    num ++;
                                    break;
                                }
                            }
                        }
                    }
                    if(num > 2)
                        i_TLS_state = 2;
                    else
                        i_TLS_state = 3;
                }
            }
        }
        if(i_TLS_state == 2 && getPckCnt() == torv_flow_check_pkn && !ch_checked)
        {
            if(len_sc < len_cs * 2)
                i_TLS_state = 3;
            else
                lpCreator->record_Tor_flow(this);
        }
    }
    return bout;
}

bool tor_flow::saveObject(FILE* fp, uint64_t cntP, bool bFin)
{
    bool bout = false;
    char buf_IPP[UINT8_MAX];
    char buf_info[1024];
    int head_tls = 29;

    if(!lp_TLS_flow)
        return false;

    if(lp_TLS_flow->get_TLS_version() == 3)
        head_tls = 22;

    if(fp)
    {
        if(len_sc > len_cs*4 && lp_TLS_flow && 
                (i_TLS_state==2 || i_TLS_state==4))
        {
            vector<stt_TLS_record> *lp_records = lp_TLS_flow->get_TLS_vector();
            for(vector<stt_TLS_record>::iterator iter=lp_records->begin(); iter!=lp_records->end(); ++iter)
                if((*iter).content_type==23)
                    (*iter).len_TLS -= head_tls;
            if(check_tor_flow(lp_records))
            {
                CPacketTools::getStr_IPportpair_from_hashbuf(bufKey, lenKey, buf_IPP);
                sprintf(buf_info, "Info.,%s,SNI,%s,,,Pck.,%u,TLS_ver,1.%d,", 
                        buf_IPP, str_SNI.c_str(), getPckCnt(), lp_TLS_flow->get_TLS_version()); 
                if(lp_TLS_flow->is_http2())
                    strcat(buf_info, "H2\n");
                else
                    strcat(buf_info, "\n");
                fprintf(fp, "%s", buf_info);

                string strPck = "packet", strTime = "time", strFrag_c = "Fragment_c", strFrag_s = "Fragment_s";
                for(vector<stt_TLS_record>::iterator iter=lp_records->begin(); iter!=lp_records->end(); ++iter)
                {

                    if((*iter).content_type==23)
                    {
                        strPck += "," + to_string((*iter).pck_no);
                        char buf_time[50];
                        sprintf(buf_time, "%d.%06d", (*iter).tm_pck.tv_sec, (*iter).tm_pck.tv_usec);
                        strTime += "," + string(buf_time);
                        if(!(*iter).b_sc)
                        {
                            strFrag_c += "," + to_string((*iter).len_TLS);
                            strFrag_s += ",";
                        }
                        else
                        {
                            strFrag_s += "," + to_string((*iter).len_TLS);
                            strFrag_c += ",";
                        }
                        lpCreator->add_TLS_stat((*iter).len_TLS);
                    }
                }
                fprintf(fp, "%s\n", strPck.c_str());
                fprintf(fp, "%s\n", strTime.c_str());
                fprintf(fp, "%s\n", strFrag_s.c_str());
                fprintf(fp, "%s\n", strFrag_c.c_str());
                fprintf(fp, "\n");

                lpCreator->add_tor_flow(lp_records);
                //arrange_tor_adu(lp_records, 600);
                //save_ADU(buf_info);
                //vector<stt_HTTP_ADU> *lp_adu = lp_TLS_flow->get_ADU_vector();
                //save_ADU(lp_adu, buf_info);
            }
        }
        bout = true;

    }
    return bout;
}

bool tor_flow::check_tor_flow(std::vector<stt_TLS_record> *lp_rec)
{
    bool bout = false;

    int cnt_c_tls = 0, cnt_c_tor = 0;
    for(vector<stt_TLS_record>::iterator iter=lp_rec->begin(); iter!=lp_rec->end(); ++iter)
    {
        if((*iter).content_type==23 && !(*iter).b_sc)
        {
            cnt_c_tls ++;
            if((*iter).len_TLS % frequ_c_len==0 || (*iter).len_TLS % frequ_max_len==0)
                cnt_c_tor ++;
        }
    }
    if(cnt_c_tor*2 > cnt_c_tls)
        bout = true;

    return bout;
}

