#include <iostream>
#include <cstring>
#include <time.h>
#include <bits/stdc++.h>

#include "_lib.h/libconfig.h++"
#include "_lib.h/libPcapSE.h"
#include "winlin/winlinux.h"
#include "tor_video/torv_flow.h"

using namespace std;  
using namespace libconfig;

int main(int argc, char *argv[])
{
    char buf[UINT8_MAX] = "data.cfg";

    if(argc==2)
        strcpy(buf, argv[1]);

    std::cerr << "tor data begin" << std::endl;        

    Config cfg;
    try
    {
        cfg.readFile(buf);
    }
    catch(...)
    {
        std::cerr << "I/O error while reading file." << std::endl;
        return(EXIT_FAILURE);
    }    

    try
    {
        //path
        string path = cfg.lookup("TOR_path");    
        cout << "path name: " << path << endl;
        string path_file = path + "0_path.tor.reverse.adu.csv";    
//        cout << "output path name: " << path_out << endl;
        string filter = cfg.lookup("TOR_SNI_filter");    
        cout << "SNI filter: " << filter << endl;
        int min_pck;
        cfg.lookupValue("TOR_min_pck", min_pck);
        cout << "threshold of packets:" << min_pck << endl;
        int thresh_1, thresh_2, thresh_3, thresh_4;
        cfg.lookupValue("TOR_threshold_1", thresh_1);
        cout << "threshold 1(ms):" << thresh_1 << endl;
        cfg.lookupValue("TOR_threshold_2", thresh_2);
        cout << "threshold 2(s):" << thresh_2 << endl;
        cfg.lookupValue("TOR_threshold_3", thresh_3);
        cout << "threshold 3(ms):" << thresh_3 << endl;
        cfg.lookupValue("TOR_threshold_4", thresh_4);
        cout << "min ADU len:" << thresh_4 << endl;
        if(thresh_1 <=0 || thresh_2 <= 0 || thresh_3 <= 0 || thresh_4 < 4096)
        {
            cout << "threshold error!" << endl;
            return 1;
        }

        if(path.length()>0)
        {
            vector<string> vctFN;
            if(iterPathPcaps(path, &vctFN))
            {
                FILE *fp = fopen(path_file.c_str(), "wt");
                if(fp)
                {
                    fprintf(fp, "file,,");
                    for(int i = 1; i<=100; i++)
                        fprintf(fp, "aud-%d,", i);
                    fprintf(fp, "\n");
                    fclose(fp);
                }
                else
                    cout << path_file << " open error!" << endl;

                for(vector<string>::iterator iter=vctFN.begin(); iter!=vctFN.end(); ++iter)
                {
                    string strFN = *iter;
                    cout << "pcap file:" << strFN << endl;

                    packet_statistics_object_type typeS = pso_IPPortPair;
                    IFlow2Stat* lpFS = CFlow2StatCreator::create_flow2_stat(strFN, 25, min_pck, 1);
                    I_TLS_flow_stat* lp_TLS = TLS_flow_stat_creator::create_TLS_flow_stat();
                    if(lp_TLS->check_stat_buffer())
                    {
                        tor_flow_creator* lp_tor = new tor_flow_creator(typeS, strFN, 
                                                                            lp_TLS, filter, min_pck, true);
                        if(lpFS && lp_tor)
                        {
                            lp_tor->set_thresholds(thresh_1, thresh_2, thresh_3, thresh_4);
                            lpFS->setParameter(typeS, 1, psm_SouDstDouble, true);
                            lpFS->setCreator(lp_tor);
                            if(lpFS->isChecked())
                            {
                                lpFS->iterPcap();
                                lp_tor->save_ADU(path_file);
                                lp_tor->save_TLS_state();
                            }
                            delete lp_tor;
                            delete lpFS;
                            delete lp_TLS;
                        }
                        else
                            cout << "pcap file " << strFN << " open error!" << endl;
                    }
                }
            }
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return(EXIT_FAILURE);
    }

    return 0;
}