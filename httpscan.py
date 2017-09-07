#!/usr/bin/env python
#coding:utf-8
#Author: linxi0428
#Version: 1.7

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
Iterations = 1

#Log-Config
logging_file_result = codecs.open('httpscan_result.txt','wb',encoding = 'utf-8')
logging_file_info = codecs.open('httpscan_info.txt','wb',encoding = 'utf-8')
logging_file_error = codecs.open('httpscan_error.txt','wb',encoding = 'utf-8')

test_list = []

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
        self.Deduplicate_list = set()
        self.dict_list_file = 'dict.txt' #open the path dictionary

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
                    
    def request(self):
        with threading.Lock():
            while self.IPs.qsize() > 0:
                ip = self.IPs.get()
                if ip == None:
                	continue
                ip = self.str_replace(ip)
                if (ip not in self.Deduplicate_list) and (ip.strip() not in self.Deduplicate_list):
                    ip_original = ip.strip()
                    self.Deduplicate_list.add(ip_original)
                    self.Deduplicate_list.add(ip)
                    try:
                        s = requests.Session()
                        s.mount('https:', Ssl3HttpAdapter()) #Mount All Https to ssl.PROTOCOL_SSLV3
                        r = s.get(str(ip).strip(),headers=header,timeout=TimeOut,verify=False,allow_redirects=False)
                        try:
                            self.get_url_to_queue(ip,response=r)
                        except Exception,e:
                            rewrite_logging('ERROR-1',e)
                        status = r.status_code
                        
                        title = re.search(r'<title>(.*)</title>', r.text) #get the title
                        if title:
                            title = title.group(1).strip()[:30]
                        else:
                            title = "No Title Field"

                        if ((status == 301) or (status == 302)) and ('404' not in title):
                            if 'Location' in r.headers:
                                try:
                                    location = r.headers['Location']
                                    self.redirect_handler_func(ip,location)
                                except Exception,e:
                                    rewrite_logging('ERROR-2',e)
                        else:
                            try:
                                if 'Server' in r.headers:
                                    banner = r.headers['Server'][:20] #get the server banner
                                else:
                                    banner = 'No Server Field'
                                self.log_func(ip,ip_original,status,banner,title)
                            except Exception,e:
                                message = 'Current IP is %s,the error is %s'  % (ip,e)
                                rewrite_logging('ERROR-3',message)
                                self.log_func(ip,ip_original,status,banner,title)
                    except Exception,e:
                        message = 'Current IP is %s,the error is %s'  % (ip,e)
                        rewrite_logging('ERROR-4',message)
    
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

    def redirect_handler_func(self,ip,location):
        loc_urlparse = urlparse.urlparse(location)
        ip_urlparse = urlparse.urlparse(ip)
        if loc_urlparse.netloc.split(':')[0] == ip_urlparse.netloc.split(':')[0]:
            if location.strip() not in self.Deduplicate_list:
                self.IPs.put(location.strip())
                self.Deduplicate_list.add(location.strip())
                rewrite_logging('INFO','rejoin the 302 url %s' % location)

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
                                if (rejoin_queue_ip_original not in self.Deduplicate_list) and \
                                    (rejoin_queue_ip not in self.Deduplicate_list):
                                    self.IPs.put(rejoin_queue_ip_original)
                            self.Deduplicate_list.add(rejoin_queue_ip)
                            self.Deduplicate_list.add(rejoin_queue_ip_original)
    
    def print_log(self,ip,status,banner,title):
        message = "|%-66s|%-6s|%-14s|%-30s|" % (ip.strip(),status,banner,title)
        rewrite_logging('Result',message)

    def get_url_to_queue(self,ip,response):
        page = etree.HTML((response.text.encode('utf-8')).decode('utf-8'))
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
            if not all_url[x].startswith('/') and not all_url[x].startswith('http'):
                all_url[x] = '/' + all_url[x]
            reqs.add(self.url_valid(all_url[x], orig_url))
    
        for x in xrange(0,len(list(reqs))):
            req = list(reqs)[x]
            if req not in self.Deduplicate_list:
                self.IPs.put(req)
                self.Deduplicate_list.add(req)
    
    def url_valid(self,url,orig_url):
        if url == None:
            return
        if '://' not in url:
            proc_url = self.url_processor(orig_url)
            url = proc_url[1] + proc_url[0] + url
        else:
            url_parse = self.url_processor(url)
            orig_url_parse = self.url_processor(orig_url)
            if url_parse[0].split(':')[0] != orig_url_parse[0].split(':')[0]:
                return
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
            rewrite_logging('ERROR-5','Could not parse url: %s' % url)
            return
    
        return (netloc, protocol, doc_domain, path)

class portscan():
    def __init__(self,cidr,threads_num,file_source,ports):
        self.threads_num = threads_num
        self.ports = ports
        self.IPs = Queue.Queue()
        self.file_source = file_source
        self.open_ports = set() #ip-port lists

        if self.file_source == None:
            try:
                self.cidr = IP(cidr)
            except Exception,e:
                rewrite_logging('ERROR-6',e)
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
                self.IPs.task_done()
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
                                    self.open_ports.add(open_list)
                                    message = 'the target %s has opened port %s' % (tgthost,tgtport)
                                    rewrite_logging('Result',message)
                                    print message + '\n'
                                else:
                                    open_list = str(item.strip()) + ':' + str(tgtport)
                                    self.open_ports.add(open_list)
                                    message = 'the target %s has opened port %s' % (item.strip(),tgtport)
                                    rewrite_logging('Result',message)
                                    print message + '\n'
                except Exception, e:
                    rewrite_logging('ERROR-7',e)

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
    if level == 'Result':
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
