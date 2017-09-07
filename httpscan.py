#!/usr/bin/env python
#coding:utf-8
#Author: linxi0428
#Version: 1.8

from __future__ import division

import re
import os
import sys
import ssl
import time
import logging
import optparse
import requests
import signal
import socket
import nmap
import logging
import threading
import Queue
import codecs
import urlparse
import pdb

from lxml import etree
from IPy import IP
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

#Config the default encoding
reload(sys)
sys.setdefaultencoding("utf8")

#Set the request in ssl with unverified cert and disable_warnings
ssl._create_default_https_context = ssl._create_unverified_context
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
#import requests.packages.urllib3.util.ssl_ 
#requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'

#Request Timeout
TimeOut = 5

#The iterations of the directory
Iterations = 3

#Log-Config
logging_file_result = codecs.open('httpscan_result.txt','wb',encoding = 'utf-8')
logging_file_info = codecs.open('httpscan_info.txt','wb',encoding = 'utf-8')
logging_file_error = codecs.open('httpscan_error.txt','wb',encoding = 'utf-8')

#test_list = []

#The Deduplicate_lists
Deduplicate_list = set()

#Filter out the non-HTTP port
nohttp_ports = [21,22,23,25,53,135,137,139,445,873,1433,1521,1723,3306,3389,5800,5900]

#User-Agent
header = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 \
          (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36','Connection':'close'}

#Transport adapter" that allows us to use SSLv3
class Ssl3HttpAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_SSLv3)

class httpscan():
    def __init__(self,cidr,threads_num,open_ports):
        self.threads_num = threads_num
        self.IPs = Queue.Queue() #build ip queue
        self.open_ports = open_ports
        self.dict_list_file = 'dict.txt' #open the path dictionary

        #Process Bar Config
        with open(self.dict_list_file,'r') as dict_lists:
            self.dict_num = len(dict_lists.readlines())
        self.port_num = len(open_ports)
        self.all_num = (self.port_num * self.dict_num)* 2
        self.bar = '#'

        #self.test = test_list
        with open(self.dict_list_file,'r') as dict_lists:
            for dict_line in dict_lists.readlines():
                dict_line = dict_line.strip()
                for open_port in list(self.open_ports):
                    if open_port.strip().endswith('80'):
                        self.IPs.put("http://"+str(open_port)+str(dict_line))
                    elif open_port.strip().endswith('443'):
                        self.IPs.put("https://"+str(open_port)+str(dict_line))
                    else:
                        self.IPs.put("http://"+str(open_port)+str(dict_line))
                        self.IPs.put("https://"+str(open_port)+str(dict_line))
        self.qsize = self.IPs.qsize()

    def request(self):
        with threading.Lock():
            while self.IPs.qsize() > 0:
                ip = self.IPs.get()
                unfinished_num = self.IPs.unfinished_tasks
                #self.progress_bar(unfinished_num) #Wait to do
                if ip == None:
                    continue
                ip_original = ip.strip()
                ip = self.str_replace(ip)
                ip_unparse = self.url_unparse_func(ip)
                if (ip not in Deduplicate_list) and (ip_unparse not in Deduplicate_list):
                    Deduplicate_list.add(ip)
                    Deduplicate_list.add(ip_original)
                    Deduplicate_list.add(ip_unparse)
                    #self.test.append(ip.strip())
                    try:
                        s = requests.Session()
                        s.mount('https:', Ssl3HttpAdapter()) #Mount All Https to ssl.PROTOCOL_SSLV3
                        r = s.get(str(ip).strip(),headers=header,timeout=TimeOut,verify=False,allow_redirects=False)
                        
                        #get_http_parameter
                        res_para = self.get_response_para(ip,response=r)
                        status = res_para[0]
                        title = res_para[1]

                        try:
                            if (self.get_url(ip,response=r)) != None:
                                reqs = self.get_url(ip,response=r)
                                for x in xrange(0,len(reqs)):
                                    req = reqs[x]
                                    if req == None:
                                        continue
                                    if req not in Deduplicate_list:
                                        self.IPs.put(req)
                                        self.qsize += self.dict_num
                                        Deduplicate_list.add(req)
                                    #when the url is like 'https://www.test.com/1/2/3/4.php?id=4' 
                                    #put 'https://www.test.com/1/' and 'https://www.test.com/1/2/' and 'https://www.test.com/1/2/3/' to the queue
                                    req_url_directory_lists = self.url_parse_func(req)
                                    self.reqs_parse_to_queue(req_url_directory_lists)
                        except Exception,e:
                            rewrite_logging('ERROR-6','the current ip is %s and the error is %s' % (ip,e))

                        if ((status == 301) or (status == 302)) and ('404' not in title):
                            if 'Location' in r.headers:
                                try:
                                    location = r.headers['Location']
                                    self.redirect_handler_func(ip,location)
                                except Exception,e:
                                    rewrite_logging('ERROR-5','the current ip is %s and the error is %s' % (ip,e))
                        else:
                            try:
                                if 'Server' in r.headers:
                                    banner = r.headers['Server'][:20] #get the server banner
                                else:
                                    banner = 'No Server Field'
                                self.log_func(ip,ip_original,status,banner,title)
                            except Exception,e:
                                message = 'Current IP is %s,the error is %s'  % (ip,e)
                                rewrite_logging('ERROR-1',message)
                                self.log_func(ip,ip_original,status,banner,title)
                    except Exception,e:
                        message = 'Current IP is %s,the error is %s'  % (ip,e)
                        rewrite_logging('ERROR-2',message)
                self.IPs.task_done()
    
    def run(self):#Multi thread
        signal.signal(signal.SIGINT, quit)
        signal.signal(signal.SIGTERM, quit)
        for i in range(self.threads_num):
            t = threading.Thread(target=self.request)
            t.setDaemon(True)
            t.start()
        while True:
            if not t.isAlive():
                break

    def get_response_para(self,ip,response):
        #get the status
        status = response.status_code
    
        #get the title
        title = re.search(r'<title>(.*)</title>', response.text)
        if title:
            title = title.group(1).strip()[:30]
        else:
            title = "No Title Field"

        #get the private ip
        private_ip = re.search(r'((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)', response.text)
        if private_ip:
            rewrite_logging('Result_Find_IP','Get %s from url : %s' % (private_ip.group(),ip))

        return (status,title)

    def redirect_handler_func(self,ip,location):
        loc_urlparse = urlparse.urlparse(location)
        ip_urlparse = urlparse.urlparse(ip)
        if loc_urlparse.netloc.split(':')[0] == ip_urlparse.netloc.split(':')[0]:
            if location.strip() not in Deduplicate_list:
                self.IPs.put(location.strip())
                Deduplicate_list.add(location.strip())
                rewrite_logging('INFO','rejoin the 302 url %s' % location)

            #rejoin the url_directory of locations
            if location != None:
                location_url_directory_lists = self.url_parse_func(location)
                if location_url_directory_lists != None:
                    for x in xrange (0,len(location_url_directory_lists)):
                        url_directory_list = location_url_directory_lists[x]
                        if url_directory_list not in Deduplicate_list:
                            self.IPs.put(url_directory_list)
                            Deduplicate_list.add(url_directory_list)
                            rewrite_logging('INFO','rejoin the url directory from url of 301/302 :  %s' % url_directory_list)

    def str_replace(self,ip): #Replace 'https://test.com//1//2//3//4/(//)' to 'https://test.com/1/2/3/4/'
        new_ip = ip.split('://')[0] + '://'
        new_ip = new_ip + ip.split('://')[1].replace('//','/')
        return new_ip

    def log_func(self,ip,ip_original,status,banner,title):
        if (status != 400) and (status != 403) and (status != 404) and ('404' not in str(title)):
            self.print_log(ip,status,banner,title)
        if (status != 400) and (status != 404) and ('404' not in str(title)):
            self.rejoin_queue(ip,ip_original,status)

    def rejoin_queue(self,ip,ip_original,status):
        if (ip.strip().endswith('/')):
            if (status == 200) or (status == 403) or (status == 501):
                with open(self.dict_list_file,'r') as dict_lists:
                    for dict_line in dict_lists.readlines():
                        dict_line = dict_line.strip()
                        if dict_line != '/':
                            rejoin_queue_ip = str(ip).strip() + str(dict_line)
                            rejoin_queue_ip_original = str(ip_original).strip() + str(dict_line)
                            if rejoin_queue_ip_original.count('//') <= (Iterations+1): #Judge the count of Iterations
                                if (rejoin_queue_ip_original not in Deduplicate_list) and \
                                    (rejoin_queue_ip not in Deduplicate_list):
                                    self.IPs.put(rejoin_queue_ip_original)
                                    self.qsize += self.dict_num
                            Deduplicate_list.add(rejoin_queue_ip)
                            Deduplicate_list.add(rejoin_queue_ip_original)
    
    def print_log(self,ip,status,banner,title):
        message = "|%-66s|%-6s|%-14s|%-30s|" % (ip.strip(),status,banner,title)
        rewrite_logging('Result',message)

    def get_url(self,ip,response):
        #pdb.set_trace()
        try:
            page = etree.HTML((response.text.encode('utf-8')).decode('utf-8'))

        except Exception,e:
            return
            rewrite_logging('ERROR-7','the current ip is %s and the error is %s' % (ip,e))
        #page = etree.HTML(response.text)
        #pdb.set_trace()
        reqs = set()
        orig_url = response.url
    
        #get_href_reqs
        href_url = []        
        link_href_url = page.xpath("//link/@href")
        a_href_url = page.xpath("//a/@href")
        li_href_url = page.xpath("//li/@href")
        href_url = link_href_url + a_href_url + li_href_url
        
        #get_src_reqs
        src_url = []        
        img_src_url = page.xpath("//img/@src")
        script_src_url = page.xpath("//script/@src")
        src_url = img_src_url + script_src_url
    
        all_url = []
        all_url = href_url + src_url

        for x in xrange(0,len(all_url)):
            if '/' not in all_url[x]: #Exclude like 'Javascript:void(0)'
                continue
            if not all_url[x].startswith('/') and not all_url[x].startswith('http'):
                if self.url_processor(orig_url)[0].split(':')[0] != all_url[x].split('/')[0]:
                    all_url[x] = '/' + all_url[x]
            if all_url[x].startswith('//'):
                if self.url_processor(orig_url)[0].split(':')[0] == all_url[x].split('//')[1].split('/')[0]:
                    all_url[x] = self.url_processor(orig_url)[1] + all_url[x].split('//')[1]
            reqs.add(self.url_valid(all_url[x], orig_url))

        return list(reqs)

    def reqs_parse_to_queue(self,req_url_directory_lists):
        #rejoin the url_directory of reqs
        if req_url_directory_lists == None:
            return
        for x in xrange (0,len(req_url_directory_lists)):
            req_directory_list = req_url_directory_lists[x]
            if req_directory_list not in Deduplicate_list:
                self.IPs.put(req_directory_list)
                Deduplicate_list.add(req_directory_list)
                rewrite_logging('INFO','rejoin the url directory from url  of get_url_reqs:  %s' % req_directory_list)

    def url_valid(self,url,orig_url):
        if url == None:
            return
        if url.startswith('http'): # like https://www.test.com/app/mobile/1.php?id=1
            url_parse = self.url_processor(url)
            orig_url_parse = self.url_processor(orig_url)
            if url_parse[0].split(':')[0] != orig_url_parse[0].split(':')[0]:
                return
        elif not url.startswith('/'):# like www.test.com/app/mobile/1.php?id=1
            proc_url = self.url_processor(orig_url)
            url = proc_url[1] + url
        elif '://' not in url: #like /app/mobile/1.php?id=1
            proc_url = self.url_processor(orig_url)
            url = proc_url[1] + proc_url[0] + url
        else: 
            proc_url = self.url_processor(orig_url)
            url = proc_url[1] + url
        return url
    
    def url_processor(self,url): # Get the url domain, protocol, and netloc using urlparse
        try:
            parsed_url = urlparse.urlparse(url)
            path = parsed_url.path
            protocol = parsed_url.scheme+'://'
            hostname = parsed_url.hostname
            netloc = parsed_url.netloc
            doc_domain = '.'.join(hostname.split('.')[-2:])
        except:
            rewrite_logging('ERROR-9','Could not parse url: %s' % url)
            return
    
        return (netloc, protocol, doc_domain, path)
    
    def progress_bar(self,unfinished_num):
        #sys.stdout.write(str(int((qsize/self.all_num)*100))+'% '+bar+'->'+ "\r")
        finished_num = self.qsize - unfinished_num
        sys.stdout.write(str(int((finished_num/self.qsize)*100))+'% ')
        sys.stdout.flush()
        #time.sleep(0.5)
        #print
        #return

    def url_parse_func(self,url):
        #when the url is like 'https://www.test.com/1/2/3/4.php?id=4' 
        #put 'https://www.test.com/1/' and 'https://www.test.com/1/2/' and 'https://www.test.com/1/2/3/' to the queue
        url_par = urlparse.urlparse(url)
        url_split = url_par.path.split('/')
        url_new = '/'
        url_list = set()
        if len(url_split) >= 3:
            for x in xrange(1,(len(url_split)-1)):
                url_new = url_new+url_split[x]+'/'
                url_list.add(url_par.scheme+'://'+url_par.netloc+url_new)
        
        return list(url_list)
    
    def url_unparse_func(self,url):
        #when the url is like 'https://www.baidu.com:443/1/2/3/4.php?id=1'
        #return 'https://www.baidu.com:443/1/2/3/4.php?id=1' and 'https://www.baidu.com/1/2/3/4.php?id=1' to put to the Deduplicate_list
        url_parse = urlparse.urlparse(url)
        if len(url_parse.netloc.split(':')) > 1:
            if (url_parse.netloc.split(':')[1] == '80') or (url_parse.netloc.split(':')[1] == '443'):
                netloc = url_parse.netloc.split(':')[0]
                return urlparse.urlunparse((url_parse.scheme,netloc,url_parse.path,url_parse.params,url_parse.query,url_parse.fragment))

class portscan():
    def __init__(self,cidr,threads_num,file_source,ports):
        self.threads_num = threads_num
        self.ports = ports
        self.IPs = Queue.Queue()
        self.file_source = file_source
        self.open_ports = set() #ip-port lists
        self.nohttp_ports = nohttp_ports

        if self.file_source == None:
            try:
                self.cidr = IP(cidr)
            except Exception,e:
                rewrite_logging('ERROR-3',e)
            for ip in self.cidr:
                ip = str(ip)
                self.IPs.put(ip)
        else:
            with open(self.file_source,'r') as file_ip:
                for line in file_ip:
                    self.IPs.put(line)

    def nmapScan(self):
        with threading.Lock():
            while self.IPs.qsize() > 0:
                item = self.IPs.get()
                try:
                    nmScan = nmap.PortScanner()
                    nmScan.scan(item,arguments = self.ports.read())
                    for tgthost in nmScan.all_hosts():
                        for tgtport in nmScan[tgthost]['tcp']:
                            tgthost = tgthost.strip()
                            tgtport = int(tgtport)
                            if nmScan[tgthost]['tcp'][tgtport]['state'] == 'open':
                                if self.file_source ==None:
                                    open_list = str(tgthost) + ':' + str(tgtport)
                                    message = 'the target %s has opened port %s' % (tgthost,tgtport)
                                    if tgtport not in self.nohttp_ports:
                                        self.open_ports.add(open_list)
                                    rewrite_logging('Result',message)
                                    print message + '\n'
                                else:
                                    open_list = str(item.strip()) + ':' + str(tgtport)
                                    message = 'the target %s has opened port %s' % (item.strip(),tgtport)
                                    if tgtport not in self.nohttp_ports:
                                        self.open_ports.add(open_list)
                                    rewrite_logging('Result',message)
                                    print message + '\n'
                except Exception, e:
                    rewrite_logging('ERROR-4',e)
                self.IPs.task_done()            

    def run(self):
        threads = [threading.Thread(target=self.nmapScan) for i in range(self.threads_num)]
        for thread in threads:
            thread.setDaemon(True)
            thread.start()
        for thread in threads:
            thread.join()

        while True:
            if not thread.isAlive():
                break
        return self.open_ports

def help():
    print "Example:"
    print "  python "+sys.argv[0]+" -f domain_list.txt"
    print "  python "+sys.argv[0]+" 1.1.1.0/24"

def quit(signum, frame): #Judge Child Thread's Statue(Exit or Not)!
    print '\nYou choose to stop me!!'
    sys.exit()

def rewrite_logging(level,message):
    log = "[%s] %s: %s" % (time.asctime(),level,message)
    if 'Result' in level:
        logging_file_result.write(log)
        logging_file_result.write('\n')
    elif 'ERROR' in level:
        logging_file_error.write(log)
        logging_file_error.write('\n')
    else:
        logging_file_info.write(log)
        logging_file_info.write('\n')

def startscan(port,cidr,threads_num,file_source):
    ports = open(port,'r')
    print "------------------------------------------------------------------------------"
    print '# Start Port Scan\n'
    scan_port = portscan(cidr=cidr,threads_num=3,file_source=file_source,ports=ports)
    open_ports = scan_port.run()
    print '# Port Scan Ends\n'
    print "------------------------------------------------------------------------------"
    print '# Start Http Scan\n'
    s = httpscan(cidr=cidr,threads_num=threads_num,open_ports=open_ports)
    s.run()
    '''
    with open('test.txt','a') as f:
        for x in xrange(0,len(test_list)):
            f.write(test_list[x])
            f.write('\n')
    '''

if __name__ == "__main__":
    parser = optparse.OptionParser("Usage: %prog [target or file] [options] ")
    parser.add_option("-t", "--thread", dest = "threads_num",\
                      default = 100, help = "number of theads,default=100")
    parser.add_option("-f", "--file", dest = "file_source",\
                      help = "source of file,default=domain_list.txt")
    (options, args) = parser.parse_args()

    if options.file_source == None:
        if len(args) < 1:
            parser.print_help()
            help()
            sys.exit(0)
        else:
            startscan(port='port.txt',cidr=args[0],threads_num=options.threads_num,file_source=None)
    else:
        startscan(port='port.txt',cidr=None,threads_num=options.threads_num,file_source=options.file_source)
