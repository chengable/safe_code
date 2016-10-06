import socket
import re
import requests
import urlparse
import urllib
from socket import inet_aton
from struct import unpack
from requests.utils import requote_uri
  
def check_ssrf(url):
    hostname = urlparse.urlparse(url).hostname
      
    def ip2long(ip_addr):
        return unpack("!L", inet_aton(ip_addr))[0]
      
    def is_inner_ipaddress(ip):    
        ip = ip2long(ip)    
        return ip2long('127.0.0.0') >> 24 == ip >> 24 or \
               ip2long('10.0.0.0') >> 24 == ip >> 24 or \
               ip2long('172.16.0.0') >> 20 == ip >> 20 or \
               ip2long('192.168.0.0') >> 16 == ip >> 16    
                 
    try:
        if not re.match(r"^(http|https)?://.*(/)?.*$", url):            
            print "url format error"
            return False,"url format error"
        ip_address = socket.getaddrinfo(hostname, 'http')[0][4][0]
        if is_inner_ipaddress(ip_address):            
            print "inner ip address attack"
            return False,"inner ip address attack"
        return True,"success"    
          
    except:
        print 'unknow error'
        return False,'unknow error'

def safe_request_url(url, **kwargs):
    def _request_check_location(r, *args, **kwargs):        
        if not r.is_redirect:            
            return        
             
        url = r.headers['location']        
         
        # The scheme should be lower case...        
        parsed = urlparse.urlparse(url)        
        url = parsed.geturl()        
        # Facilitate relative 'location' headers, as allowed by RFC 7231.        
        # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')        
        # Compliant with RFC3986, we percent encode the url.        
        if not parsed.netloc:            
            url = urljoin(r.url, requote_uri(url))        
        else:            
            url = requote_uri(url)        
        succ, errstr = check_ssrf(url)
        if not succ:            
            print "SSRF Attack: %s" % (errstr)
            raise requests.exceptions.InvalidURL("SSRF Attack: %s" % (errstr, ))
         
    success, errstr = check_ssrf(url)    
    if not success:        
        print "SSRF Attack: %s" % (errstr)
        raise requests.exceptions.InvalidURL("SSRF Attack: %s" % (errstr,))
         
    all_hooks = kwargs.get('hooks', dict())    
    if 'response' in all_hooks:        
        if hasattr(all_hooks['response'], '__call__'):            
            r_hooks = [all_hooks['response']]        
        else:            
            r_hooks = all_hooks['response']        
             
        r_hooks.append(_request_check_location)    
         
    else:
        r_hooks = [_request_check_location]    
         
    all_hooks['response'] = r_hooks   
    kwargs['hooks'] = all_hooks    
    return requests.get(url, **kwargs)

