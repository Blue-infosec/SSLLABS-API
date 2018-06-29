#!/usr/bin/env python
from __future__ import unicode_literals
import requests
import logging
import sys
import urllib
import StringIO
import pycurl
import json
import time

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

class SSLLabsAPI():
    """
         Uses SSL Labs API to check security status of your SSL server
    """

    def __init__(self,use_proxy=False, proxy_auth_type='basic', timeout_period=60, proxy_host=None, proxy_port=8080, proxy_user=None, proxy_password=None):
  
       self.base_url = 'https://api.ssllabs.com/api/v2/analyze'
       self.proxy_host = proxy_host
       self.proxy_port = proxy_port
       self.proxy_user = proxy_user
       self.proxy_password = proxy_password
       self.timeout = timeout_period 
       if use_proxy: 
           self.proxies = {"http":"http://%s:%s@%s:%s" % (proxy_user, proxy_password, proxy_host, proxy_port),
                           "https":"http://%s:%s@%s:%s" % (proxy_user, proxy_password, proxy_host, proxy_port)
                }
       else:
           self.proxies = None

       self.use_proxy = use_proxy
       self.proxy_auth_type = proxy_auth_type
 

    def request_API(self, payload=dict()):

        '''This method forms the URL as desired by SSL Labs and returns JSON formatted data response'''

        url = self.base_url 
        data = None

        try:
            if self.proxies:
                response = requests.get(url, params=payload, verify=False,proxies=self.proxies,timeout=self.timeout)
            else:
                 response = requests.get(url, params=payload, verify=False,timeout=self.timeout)
            data = response.json()

        except Exception,e:
            logger.error('Error while getting response from SSL Labs API - %s' % e.message,exc_info=True)
            sys.exit(1)

        return data

    def pycurl_API(self,payload=dict()):

        '''This method forms the URL as desired by SSL Labs and returns JSON formatted data response using pycurl'''

        url = self.base_url 
        data = None
        # pass the parameters 
        payload_parameters = urllib.urlencode(payload)
        full_url = url + '?' + payload_parameters

        try:
            if self.use_proxy:
                if (self.proxy_auth_type).lower() == 'digest':
                    proxy_auth_mode = pycurl.HTTPAUTH_DIGEST
                    # proxy_auth_mode = pycurl.HTTPAUTH_BASIC
                elif (self.proxy_auth_type).lower() == 'basic':
                    proxy_auth_mode = pycurl.HTTPAUTH_BASIC
                output = StringIO.StringIO()
                curl_instance = pycurl.Curl()
                curl_instance.setopt(pycurl.USERAGENT, 'Mozilla/57.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36')
                curl_instance.setopt(pycurl.PROXY, self.proxy_host)
                curl_instance.setopt(pycurl.PROXYPORT, self.proxy_port)
                curl_instance.setopt(pycurl.PROXYAUTH, proxy_auth_mode)
                curl_instance.setopt(pycurl.PROXYUSERPWD, "{}:{}".format(self.proxy_user, self.proxy_password))
                #curl_instance.setopt(pycurl.POSTFIELDS, payload)
                curl_instance.setopt(curl_instance.URL, full_url)
                curl_instance.setopt(curl_instance.WRITEDATA, output)
                curl_instance.perform()
                response = output.getvalue()
                curl_instance.close()   
                data = response            
            else:
                if self.url:
                    response = requests.get(self.url)
                    if response.status_code == 200:
                        data = response.text
                        logger.debug("%s" % self.feed_data)   

        except Exception,e:
            logger.error('Error while getting response from SSL Labs API - %s' % e.message,exc_info=True)
            sys.exit(1)

        return data


    def new_scan(self, arg_host=None, arg_publish='off', arg_startNew='on',arg_all='done', arg_fromCache='off',arg_ignoreMismatch='on', arg_maxAge=48):

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

        #results = self.request_API(payload)
        results = self.pycurl_API(payload)
        # wait for couple of minutes to get the results
        time.sleep(180)
        payload.pop('startNew')
        # convert results to json
        results= json.loads(results)
        while results['status'] != 'READY' and results['status'] != 'ERROR':
            # sleeping before another request for the results
            time.sleep(60)
            #results = self.request_API(payload)
            results = self.pycurl_API(payload)
            # convert results to json
            results= json.loads(results)
        return results

    def cache_results(self,arg_host=None, arg_publish='off', arg_startNew='off', arg_fromCache='on', arg_all='done',arg_ignoreMismatch='on', arg_maxAge=48):

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
        
        #results = self.request_API(payload)
        results = self.pycurl_API(payload)
        # convert results to json
        results= json.loads(results)
        return results
