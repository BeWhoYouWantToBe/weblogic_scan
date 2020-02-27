#!/usr/bin/env python3
# _*_ coding:utf-8 _*_ 
import pdb
import json
import os
import re
import time

import poc
import poc._import 
from multiprocessing.dummy import Pool as ThreadPool

def check_all(key):
    for group_name in poc.universe.actived:
        for proof in poc.universe.actived[group_name]:
            try:
                instance = proof()
                res, msg = instance.light_and_msg(m_target[key]['ip'], m_target[key]['port'])
                ikey = instance.info['CVE'] if instance.info['CVE'] else instance.info['NAME']
                if res == True:
                    if result.__contains__(key):
                        result[key] = result[key] + ' ' + ikey 
                    else:
                        result[key] = ikey
            except Exception as e:
                print(e)
                continue 

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--targets', required=True, nargs='+',
                        help='target, or targets file(default port 7001). eg. 127.0.0.1:7001')
    parser.add_argument('-v', '--vulnerability', nargs='+',
                        help='vulnerability name. eg. "weblogic administrator console"')
    parser.add_argument('-o', '--output', type=str, help='Path to json output(default without output).')
    args = parser.parse_args() 
    
    m_target = {}
    for target in args.targets:
        t_list = []
        if os.path.isfile(target):
            with open(target) as _f:
                for it in _f.read().split('\n'):
                    res = re.search(r'^(\d{,3}\.\d{,3}\.\d{,3}\.\d{,3})([ :](\d{,5}))?$', it.strip())
                    if res:
                        port = res.group(3) if res.group(3) else '7001'
                        id = res.group(1) + ':' + port
                        m_target[id] = {'ip': res.group(1), 'port': port}
        else:
            res = re.search(r'^(\d{,3}\.\d{,3}\.\d{,3}\.\d{,3})([ :](\d{,5}))?$', target)
            if res:
                port = res.group(3) if res.group(3) else '7001'
                id = res.group(1) + ':' + port
                m_target[id] = {'ip': res.group(1), 'port': port}

    result = {} 
    pool = ThreadPool(30) 
    pool.map(check_all,m_target)
    pool.close()
    pool.join()

    pdb.set_trace()
    with open(os.path.join(args.output, f'res_{time.strftime("%Y%m%d_%H.%M.%S", time.localtime(time.time()))}.txt'), 'w') as f:
        for i in result:
            line = i + ':' + result[i] + '\n'
            f.write(line)
            
