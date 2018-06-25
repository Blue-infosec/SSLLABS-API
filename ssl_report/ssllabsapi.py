#!/usr/bin/env python
from __future__ import unicode_literals
import requests
import logging
import sys
import argparse
#import yaml
import time

"""
    This script uses SSL Labs API to check security status of your SSL server and you can be used to improve
    security configuration of server(s) in the organization.
"""

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

class SSLLabsAPI():
    """
         Uses SSL Labs API to check security status of your SSL server
    """

    def __init__(self):
  
       self.base_url = 'https://api.ssllabs.com/api/v2/analyze'

    def request_API(self, proxies=dict(), payload=dict()):

        '''This method forms the URL as desired by SSL Labs and returns JSON formatted data response'''

        url = self.base_url 
        data = None
        #proxies = {'http':'http://xxx:xxx@192.168.1.2:3128',
        #           'https':'https://xxx:xxx@192.168.1.2:3128',
        #          } 
        try:
            response = requests.get(url, params=payload, verify=False,proxies=proxies)
            data = response.json()

        except Exception,e:
            logger.error('Error while getting response from SSL Labs API - %s' % e.message,exc_info=True)
            sys.exit(1)

        return data


    def new_scan(self, proxies=dict(), arg_host=None, arg_publish='off', arg_startNew='on',arg_all='done', arg_fromCache='off',arg_ignoreMismatch='on', arg_maxAge=48):

        results = None
        payload = {
            'host': arg_host,
            'publish': arg_publish,
            'startNew': arg_startNew,
            'all': arg_all,
            'fromCache': arg_fromCache,
            #'maxAge': arg_maxAge,
            'ignoreMismatch': arg_ignoreMismatch
        }
        
        results = self.request_API(proxies,payload)
        payload.pop('startNew')
        
        while results['status'] != 'READY' and results['status'] != 'ERROR':
            time.sleep(60)
            results = self.request_API(proxies,payload)
        
        return results

    def cache_results(self, proxies=dict(), arg_host=None, arg_publish='off', arg_startNew='off', arg_fromCache='on', arg_all='done',arg_ignoreMismatch='on', arg_maxAge=48):

        results = None

        payload = {
            'host': arg_host,
            'publish': arg_publish,
            'startNew': arg_startNew,
            'all': arg_all,
            'fromCache': arg_fromCache,
            #'maxAge': arg_maxAge,
            'ignoreMismatch': arg_ignoreMismatch
        }
        
        results = self.request_API(proxies,payload)
    
        return results

def cmd_arguments():

    try:
        parser = argparse.ArgumentParser(description = "This script uses SSL Labs API to check state of various SSL settings of HTTPS server(s) facing the internet and can be used to their improve security configuration")

        parser.add_argument('--domain', required=True, help='Please specify host',dest='domain')

        parser.add_argument('--proxy-host', required=False, help='Please specify proxy host',dest='proxy_host')
        parser.add_argument('--proxy-port', required=False, help='Please specify proxy port',dest='proxy_port')
        parser.add_argument('--proxy-user', required=False, help='Please specify proxy user',dest='proxy_user')
        parser.add_argument('--proxy-password', required=False, help='Please specify proxy password',dest='proxy_password')

        args = parser.parse_args()
        return args
    except Exception as exc:
        logger.error("Error while getting command line arguments - %s" %exc.message,exc_info=True)

if __name__ == "__main__":

    cmd_args = cmd_arguments()
    sslapi_instance = SSLLabsAPI() 
    if cmd_args.domain: 
        domain = cmd_args.domain
        domain = domain.replace('https://','').replace('http://','')
        proxy_dict = {
                      'http':'http://{}:{}@{}:{}'.format(cmd_args.proxy_user,cmd_args.proxy_password,cmd_args.proxy_host,cmd_args.proxy_port),
                      'https':'http://{}:{}@{}:{}'.format(cmd_args.proxy_user,cmd_args.proxy_password,cmd_args.proxy_host,cmd_args.proxy_port),
                     }  
        logger.info("Proxies - {}".format(proxy_dict))
        #domain_results = sslapi_instance.new_scan(proxy_dict, domain,'off','on','done','off','on',24)
        domain_results = sslapi_instance.new_scan(proxy_dict, domain)
        #domain_results = sslapi_instance.cache_results(proxy_dict, domain) 
        print domain_results

