#!/usr/bin/env python
import ast
from datetime import datetime, timedelta
import logging
from pprint import pprint 

# This program reads existing results of SSL-LABS-API scan and interprets the results
# SSL-LABS API documentation - https://github.com/ssllabs/ssllabs-scan/blob/stable/ssllabs-api-docs.md
# Thanks to https://github.com/moheshmohan/pyssltest/blob/master/pyssltest.py

#with open('webmail_response.json','r') as f:
with open('google.json','r') as f:
    res_string = f.read()

# convert string to dict using ast.literal_eval
json_ssllabs = ast.literal_eval(res_string)

def bit_set(x, n):
    """Returns if nth bit of x is set"""
    return bool(x & (1 << n)) 

def get_hour_min_sec(time_seconds):
    d = None #"Not valid"
    if time_seconds:
        sec= timedelta(seconds = int(time_seconds))
        d = datetime(1,1,1) + sec
    return d

def timestamp_to_date(t_date):
    #return datetime.fromtimestamp(int(t_date)).strftime('%Y-%m-%d %H:%M:%S')
    return datetime.fromtimestamp(int(t_date)).isoformat()

def parse_results(json_response):
    
    domain_results = dict()
    
    try:

        # host name 
        try:
            domain_results['host'] = json_response['host']
        except Exception:
            domain_results['host'] = 'NA'
            pass

        # port 
        try:
            domain_results['port'] = json_response['port']
        except Exception:
            domain_results['port'] = 'NA'
            pass

        # protocol used
        try:
            domain_results['protocol'] = json_response['protocol']
        except Exception:
            domain_results['protocol'] = 'NA'
            pass

        # Assessment status
        try:
            domain_results['assessment_status'] = json_response['status']
        except Exception:
            domain_results['assessment_status'] = 'ERROR'
            pass

        #Assessment time
        try:
            lapsed_seconds = (json_response['testTime'] - json_response['startTime'])/1000
            lapsed_time = get_hour_min_sec(lapsed_seconds)
            if lapsed_time:
                domain_results['assessment_time(hh:mm:ss)'] = '%d:%d:%d' %(lapsed_time.hour, lapsed_time.minute, lapsed_time.second)
            else:
                domain_results['assessment_time(hh:mm:ss)'] = 'NA'
        except Exception:  
            domain_results['assessment_time(hh:mm:ss)'] = 'NA'

        # IP information
        try:
            domain_results['ip'] = json_response['endpoints'][0]['ipAddress']
        except Exception:
            domain_results['ip'] = 'NA'
            pass


        # Server name information
        try:
            domain_results['server_name'] = json_response['endpoints'][0]['serverName']
        except Exception:
            domain_results['server_name'] = 'NA'
            pass


        # Grade information
        try:
            domain_results['grade'] = json_response['endpoints'][0]['grade']
        except Exception:
            domain_results['grade'] = 'NA'
            pass

        # Grade information ignoring trust issues
        try:
            domain_results['sgrade'] = json_response['endpoints'][0]['gradeTrustIgnored']
        except Exception:
            domain_results['sgrade'] = 'NA'
            pass

        # hasWarnings - if this endpoint has warnings that might affect the score (e.g., get A- instead of A).
        try:
            domain_results['grade_warnings'] = json_response['endpoints'][0]['hasWarnings']
        except Exception:
            domain_results['grade_warnings'] = 'NA'
            pass

       # isExceptional - this flag will be raised when an exceptional configuration is encountered. The SSL Labs test will give such sites an A+.
        try:
            domain_results['grade_exceptional'] = json_response['endpoints'][0]['isExceptional']
        except Exception:
            domain_results['grade_exceptional'] = 'NA'
            pass

        #delegation - indicates domain name delegation with and without the www prefix 
        try:
            prefixed_access = json_response['endpoints'][0]['delegation']
            if bit_set(prefixed_access,0):
                domain_results['domain_delegation'] = "non-prefixed access"
            elif bit_set(prefixed_access,1):
                domain_results['domain_delegation'] = "prefixed access"
        except Exception:
            domain_results['domain_delegation'] = 'NA'
            pass

        # server signature 
        try:
            server_signature = json_response['endpoints'][0]['details']['serverSignature']
            domain_results['server_signature'] = server_signature
        except Exception:
            domain_results['server_signature'] = 'NA'

        # key size 
        try:
            key_size = json_response['endpoints'][0]['details']['key']['size']
            domain_results['key_size'] = key_size
        except Exception:
            domain_results['key_size'] = 'NA'

        # key strength
        try:
            key_strength = json_response['endpoints'][0]['details']['key']['strength']
            domain_results['key_strength'] = key_strength
        except Exception:
            domain_results['key_strength'] = 'NA'

        # key algorithm
        try:
            key_algorithm = json_response['endpoints'][0]['details']['key']['strength']
            domain_results['key_algorithm'] = key_algorithm
        except Exception:
            domain_results['key_algorithm'] = 'NA'


        # beast vulnerability status 
        # Ref - https://docs.secureauth.com/pages/viewpage.action?pageId=14778519
        try:
            if json_response['endpoints'][0]['details']['vulnBeast']:
                domain_results['beast'] = "Y"
            else:
                domain_results['beast'] = "N"
        except Exception:
            domain_results['beast'] = 'NA'
            pass

        # session resumption 
        try:
            session_resumption = json_response['endpoints'][0]['details']['sessionResumption']
            if session_resumption == 2:
                domain_results['session_resumption'] = "Supported"
            else: 
                domain_results['session_resumption'] = "Not supported"
        except Exception:
            domain_results['session_resumpption'] = 'NA'
            pass

        # support for NPN protocols
        # Ref - https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html 
        try:
            if json_response['endpoints'][0]['details']['supportsNpn']:
                domain_results['npn_protocols_support'] = "Y"
            else:
                domain_results['npn_protocols_support'] = "N"
        except Exception:  
            domain_results['npn_protocols_support'] = "NA"
            pass 

        # support for session tickets
        # Ref - https://blog.filippo.io/we-need-to-talk-about-session-tickets/
        try:
            session_tickets =  json_response['endpoints'][0]['details']['sessionTickets']
            if bit_set(session_tickets,0):
                domain_results['session_tickets_support'] = "Y"
            else:
                domain_results['session_tickets_support'] = "N"
        except Exception:  
            domain_results['session_tickets_support'] = "NA"
            pass

        # support for OCSP stapling
        # Ref - https://www.thawte.com/assets/documents/whitepaper/ocsp-stapling.pdf
        try:
            if json_response['endpoints'][0]['details']['ocspStapling']:
                domain_results['ocsp_stapling_support'] = "Y"
            else:
                domain_results['ocsp_stapling_support'] = "N"
        except Exception:  
            domain_results['ocsp_stapling_support'] = "NA"
            pass  

        # support for SNI
        # Ref - https://support.comodo.com/index.php?/Knowledgebase/Article/View/1120/38/what-is-sni-and-how-it-works
        try:
            if json_response['endpoints'][0]['details']['sniRequired']:
                domain_results['SNI_support'] = "Y"
            else:
                domain_results['SNI_support'] = "N"
        except Exception:  
            domain_results['SNI_support'] = "NA"
            pass 

        # support for forward secrecy
        # Ref - https://www.digicert.com/ssl-support/ssl-enabling-perfect-forward-secrecy.htm
        try:
            forward_secrecy =  json_response['endpoints'][0]['details']['forwardSecrecy']
            if bit_set(session_tickets,0):
                domain_results['forward_secrecy_support'] = "Y"
            else:
                domain_results['forward_secrecy_support'] = "N"
        except Exception:  
            domain_results['forward_secrecy_support'] = "NA"
            pass

        # certificate transparency availability
        try:
            certificate_sct_support =  json_response['endpoints'][0]['details']['hasSct']
            if bit_set(certificate_sct_support,0) or bit_set(certificate_sct_support,1) \
            or bit_set(certificate_sct_support,2) :
                domain_results['certificate_sct_support'] = "Y"
            else:
                domain_results['certificate_sct_support'] = "N"
        except Exception:  
            domain_results['certificate_sct_support'] = "NA"
            pass

        # heartbleed attack
        # Ref - http://heartbleed.com
        # https://www.us-cert.gov/ncas/alerts/TA14-098A  
        try:
            if json_response['endpoints'][0]['details']['heartbleed']:
                domain_results['heartbleed'] = "Y"
            else:
                domain_results['heartbleed'] = "N"
        except Exception:  
            domain_results['heartbleed'] = "NA"
            pass 

        # crime vulnerability
        # Ref - https://www.acunetix.com/vulnerabilities/web/crime-ssl-tls-attack
        try: 
            if json_response['endpoints'][0]['details']['compressionMethods']!= 0 and \
             json_response['endpoints'][0]['details']['supportsNpn'] == False:
                domain_results['crime'] = "Y"
            else:
                 domain_results['crime'] = "N"
        except Exception:
            domain_results['crime'] = "NA"
            pass

        # freak vulnerability status 
        # Ref - https://www.digicert.com/blog/freak-attack-need-know/
        try:
            if json_response['endpoints'][0]['details']['freak']:
                domain_results['freak'] = "Y"
            else:
                domain_results['freak'] = "N"
        except Exception:
            domain_results['freak'] = 'NA'
            pass

        # logjam vulnerability status
        # Ref - https://blog.cloudflare.com/logjam-the-latest-tls-vulnerability-explained/
        try:
            if json_response['endpoints'][0]['details']['logjam']:
                domain_results['logjam'] = "Y"
            else:
                domain_results['logjam'] = "N"
        except Exception:
            domain_results['logjam'] = 'NA'
            pass

        # poodle vulnerability status
        try:
            poodle_response = json_response['endpoints'][0]['details']['poodle']
            if poodle_response:
                domain_results['poodle'] = "Y"
            else:
                domain_results['poodle'] = "N"
        except Exception:
            domain_results['poodle'] = 'NA'
            pass

        # poodle TLS vulnerability status
        # Ref - https://www.openssl.org/~bodo/ssl-poodle.pdf  
        try:
            poodle_response = json_response['endpoints'][0]['details']['poodleTls']

            if poodle_response == 2:
                domain_results['poodleTLS'] = "Y"
            elif poodle_response == 1:
                domain_results['poodleTLS'] = "N"
            else: 
                domain_results['poodleTLS'] = 'NA'

        except Exception:
            domain_results['poodleTLS'] = 'NA'
            pass

        # Renegotiation support 
        # Ref - https://www.digicert.com/news/2011-06-03-ssl-renego/
        # Ref - https://www.rapid7.com/db/vulnerabilities/tls-sess-renegotiation
        # renegSupport - this is an integer value that describes the endpoint support for renegotiation:
        # bit 0 (1) - set if insecure client-initiated renegotiation is supported
        # bit 1 (2) - set if secure renegotiation is supported
        # bit 2 (4) - set if secure client-initiated renegotiation is supported
        # bit 3 (8) - set if the server requires secure renegotiation support
        
        #insecure client-initiated renegotiation
        try:
            renegotation_response = json_response['endpoints'][0]['details']['renegSupport']
            if bit_set(renegotation_response,0):
                domain_results['insecure_client_renegotiation'] = "Y"
            else:
                domain_results['insecure_client_renegotiation'] = "N"
        except Exception:
            domain_results['insecure_client_renegotiation'] = 'NA'
            pass
        
        #secure renegotiation support
        try:
            renegotation_response = json_response['endpoints'][0]['details']['renegSupport']
            if bit_set(renegotation_response,1):
                domain_results['secure_renegotiation'] = "Y"
            else:
                domain_results['secure_renegotiation'] = "N"
        except Exception:
            domain_results['secure_renegotiation'] = 'NA'
            pass

        #secure client renegotiation support
        try:
            renegotation_response = json_response['endpoints'][0]['details']['renegSupport']
            if bit_set(renegotation_response,2):
                domain_results['secure_client_renegotiation'] = "Y"
            else:
                domain_results['secure_client_renegotiation'] = "N"
        except Exception:
            domain_results['secure_client_renegotiation'] = 'NA'
            pass

        #secure renegotiation -server support
        try:
            renegotation_response = json_response['endpoints'][0]['details']['renegSupport']
            if bit_set(renegotation_response,3):
                domain_results['secure_renegotiation_server_support'] = "Y"
            else:
                domain_results['secure_renegotiation_server_support'] = "N"
        except Exception:
            domain_results['secure_renegotiation__server_support'] = 'NA'
            pass

        # OpenSslCcs 
        # Ref - https://access.redhat.com/articles/904433
        # openSslCcs - results of the CVE-2014-0224 test:
        #    -1 - test failed
        #     0 - unknown
        #     1 - not vulnerable
        #     2 - possibly vulnerable, but not exploitable
        #     3 - vulnerable and exploitable
        try:
            opensslccs_response = json_response['endpoints'][0]['details']['openSslCcs']
            if opensslccs_response == 1:
                domain_results['opensslccs'] = "N"
            elif opensslccs_response == 2 or opensslccs_response == 3 :
                domain_results['opensslccs'] = "Y"
            else: # ignore test failed, unknown cases
                domain_results['opensslccs'] = "NA"
        except Exception:
            domain_results['opensslccs'] = 'NA'
            pass
        
        # openSSLLuckyMinus20
        # Ref - https://blog.cloudflare.com/yet-another-padding-oracle-in-openssl-cbc-ciphersuites/
        # openSSLLuckyMinus20 - results of the CVE-2016-2107 test:
        #   -1 - test failed
        #    0 - unknown
        #    1 - not vulnerable
        #    2 - vulnerable and insecure
        try:
            openssl_lucky_minus_response = json_response['endpoints'][0]['details']['openSSLLuckyMinus20']
            if openssl_lucky_minus_response == 1:
                domain_results['openssl_luckyminus'] = "N"
            elif openssl_lucky_minus_response == 2 :
                domain_results['openssl_luckyminus'] = "Y"
            else: # ignore test failed, unknown cases
                domain_results['openssl_luckyminus'] = "NA"
        except Exception:
            domain_results['openssl_luckyminus'] = 'NA'
            pass

        # Support for RC4 cipher
        try:
            rc4_support = json_response['endpoints'][0]['details']['supportsRc4'] 
            if rc4_support:
                domain_results['rc4'] = 'Y'
            else: 
                domain_results['rc4'] = 'N'
        except Exception:
            domain_results['rc4'] = 'NA'
            pass

        # Support for RC4 only cipher
        try:
            rc4_only = json_response['endpoints'][0]['details']['rc4Only'] 
            if rc4_only:
                domain_results['rc4_only'] = 'Y'
            else: 
                domain_results['rc4_only'] = 'N'
        except Exception:
            domain_results['rc4_only'] = 'NA'
            pass

        # Signature algorithm should not be weak like SHA1
        try:
            sig_algorithm = json_response['endpoints'][0]['details']['cert']['sigAlg'] 
            if "SHA1" in sig_algorithm:
                domain_results['sig_algorithm_weak'] = 'Y'
            else: 
                domain_results['sig_algorithm_weak'] = 'N'
        except Exception:
            domain_results['sig_algorithm_weak'] = 'NA'
            pass

        # certificate subject
        try:
            cert_subject = json_response['endpoints'][0]['details']['cert']['subject'] 
            domain_results['cert_subject'] = cert_subject
        except Exception:
            domain_results['cert_subject'] = 'NA'
            pass

        # certificate common names
        try:
            c_name = json_response['endpoints'][0]['details']['cert']['commonNames'] 
            domain_results['cert_common_names'] = c_name
        except Exception:
            domain_results['cert_common_names'] = 'NA'
            pass

        # certificate alternate names
        try:
            c_name = json_response['endpoints'][0]['details']['cert']['altNames'] 
            domain_results['cert_alt_names'] = c_name
        except Exception:
            domain_results['cert_alt_names'] = 'NA'
            pass

        # certificate validity
        try:
            valid_date = json_response['endpoints'][0]['details']['cert']['notAfter'] 
            domain_results['cert_validity'] = "%s:%s" % (valid_date,timestamp_to_date(valid_date))
        except Exception:
            domain_results['cert_validity'] = 'NA'
            pass

        # certificate issuer subject
        try:
            issuer_subject = json_response['endpoints'][0]['details']['cert']['issuerSubject'] 
            domain_results['cert_issuer_subject'] = issuer_subject
        except Exception:
            domain_results['cert_issuer_subject'] = 'NA'
            pass

        # certificate issuer label
        try:
            issuer_label = json_response['endpoints'][0]['details']['cert']['issuerLabel'] 
            domain_results['cert_issuer_label'] = issuer_label
        except Exception:
            domain_results['cert_issuer_label'] = 'NA'
            pass

        # certificate signature algorithm
        try:
            cert_signature_algo = json_response['endpoints'][0]['details']['cert']['sigAlg'] 
            domain_results['cert_signature_algo'] = cert_signature_algo
        except Exception:
            domain_results['cert_signature_algo'] = 'NA'
            pass

        # certificate revocation status
        try:
            cert_revocation_status = json_response['endpoints'][0]['details']['cert']['revocationStatus'] 
            if cert_revocvation_status == 0:
                domain_results['cert_revocation_status'] = "Not checked"
            elif cert_revocvation_status == 1:
                domain_results['cert_revocation_status'] = "Revoked"
            elif cert_revocvation_status == 2:
                domain_results['cert_revocation_status'] = "Not revoked"
            elif cert_revocvation_status == 3:
                domain_results['cert_revocation_status'] = "Revokation error"
            elif cert_revocvation_status == 4:
                domain_results['cert_revocation_status'] = "Revokation information absent"

        except Exception:
            domain_results['cert_revocation_status'] = 'NA'
            pass

        # certificate - extended validation support
        try:
            cert_extended_validation = json_response['endpoints'][0]['details']['cert']['validationType'] 
            if cert_extended_validation == 'E':
                domain_results['cert_extended_validation'] = "Y"
            else:
                domain_results['cert_extended_validation'] = "N"
        except Exception:
            domain_results['cert_signature_algo'] = 'NA'
            pass

         # cipher suites supported
        try:
            cipher_suites = json_response['endpoints'][0]['details']['suites']
            cipher_list = list()
            for item in cipher_suites['list']:
                cipher_dict = dict()
                cipher_dict.update({ 'name' : item['name'] })
                cipher_dict.update({ 'cipher_strength' : item['cipherStrength'] })
                cipher_list.append(cipher_dict)
            domain_results['cipher_suites'] = cipher_list
        except Exception:
            domain_results['cipher_suites'] = 'NA'
            pass

         # hsts policy status
        try:
            hsts_policy = json_response['endpoints'][0]['details']['hstsPolicy']
            domain_results['hsts_policy'] = hsts_policy['status']
        except Exception:
            domain_results['hsts_policy'] = 'NA'
            pass  

        return domain_results
    except Exception,e:
        logger.error("Error while parsing SSL-Labs API results - %s"%e.message,exc_info=True)

pprint (parse_results(json_ssllabs))
