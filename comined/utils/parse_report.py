#!/usr/bin/env python
import os
import sys
import json

class Parse_SSLLabs():

    def __init__(self,json_response):
        self.json_response = json_response
        self.results = dict()

    def _bit_set(self,x, n):
        """Returns if nth bit of x is set"""
        return bool(x & (1 << n)) 

    def _get_hour_min_sec(self,time_seconds):
        d = None #"Not valid"
        if time_seconds:
            sec= timedelta(seconds = int(time_seconds))
            d = datetime(1,1,1) + sec
        return d

    def _timestamp_to_date(self,t_date):
        #return datetime.fromtimestamp(int(t_date)).strftime('%Y-%m-%d %H:%M:%S')
        return datetime.fromtimestamp(int(t_date)).isoformat()

    def get_results(self):
        try:
            self.results['host'] = self.get_host()
            self.results['port'] = self.get_port()
            self.results['protocol'] = self.get_protocol()
            self.results['assessment_status'] = self.get_assessment_status()
            self.results['assessment_time'] = self.get_assessment_time()
            self.results['ip'] = self.get_ip()
            self.results['server_name'] = self.get_server_name()
            self.results['grade'] = self.get_grade()
            self.results['sgrade'] = self.get_sgrade()
            self.results['grade_warnings'] = self.get_grade_warnings()
            self.results['grade_exceptional'] = self.get_grade_exceptional()
            self.results['domain_delegation'] = self.get_domain_delegation()
            self.results['server_signature'] = self.get_server_signature()
            self.results['key_size'] = self.get_key_size()
            self.results['key_strength'] = self.get_key_strength()
            self.results['key_algorithm'] = self.get_key_algorithm()
            self.results['beast'] = self.get_beast_status()
            self.results['session_resumpption'] = self.get_session_resumption()
            self.results['npn_protocols_support'] = self.get_npn_protocol_support()
            self.results['session_tickets_support'] = self.get_session_tickets_support()
            self.results['ocsp_stapling_support'] = self.get_ocsp_stapling_support()
            self.results['SNI_support'] = self.get_sni_support()
            self.results['forward_secrecy_support'] = self.get_forward_secrecy_support()
            self.results['certificate_sct_support'] = self.get_certificate_sct_support()
            self.results['heartbleed'] = self.get_heartbleed_status()
            self.results['crime'] = self.get_crime_status()
            self.results['freak'] = self.get_freak_status()
            self.results['logjam'] = self.get_logjam_status()
            self.results['poodle'] = self.get_poodle_status()
            self.results['poodleTLS'] = self.get_poodle_tls_status()
            self.results['insecure_client_renegotiation'] = self.get_insecure_client_renegotiation_status()
            self.results['secure_renegotiation'] = self.get_secure_renegotiation_status()
            self.results['secure_client_renegotiation'] = self.get_secure_client_renegotiation_status()
            self.results['secure_renegotiation_server_support'] = self.get_secure_renegotiation_server_support()
            self.results['opensslccs'] = self.get_opensslccs_status()
            self.results['openssl_luckyminus'] = self.get_openssl_luckyminus_status()
            self.results['rc4'] = self.get_rc4_status()
            self.results['rc4_only'] = self.get_rc4_only_status()
            self.results['sig_algorithm_weak'] = self.get_weak_signature_algorithm_status()
            self.results['cert_subject'] = self.get_certificate_subject()
            self.results['cert_alt_names'] = self.get_certificate_alternate_names()
            self.results['cert_validity'] = self.get_certificate_validity()
            self.results['cert_issuer_subject'] = self.get_certificate_issuer_subject()
            self.results['cert_issuer_label'] = self.get_certificate_issuer_label()
            self.results['cert_signature_algo'] = self.get_certificate_algorithm()
            self.results['cert_revocation_status'] = self.get_certificate_revocation_status()
            self.results['cert_extended_validation'] = self.get_certificate_extended_validation_status()
            self.results['cipher_suites'] = self.get_cipher_suites()
            self.results['hsts_policy'] = self.get_hsts_status()

            return self.results

        except Exception:
            return "NA"


    def get_host(self):
        # host name 
        try:
            return self.json_response['host']
        except Exception:
            return 'NA'
    def get_port(self):
        # port 
        try:
            return self.json_response['port']
        except Exception:
            return 'NA'

    def get_protocol(self):
        # protocol used
        try:
            return self.json_response['protocol']
        except Exception:
            return 'NA'

    def get_assessment_status(self):
        # Assessment status
        try:
            return self.json_response['status']
        except Exception:
            return 'NA'

    def get_assessment_time(self):
        # Assessment time (hh:mm:ss)
        try:
            lapsed_seconds = (self.json_response['testTime'] - self.json_response['startTime'])/1000
            lapsed_time = self._get_hour_min_sec(lapsed_seconds)
            if lapsed_time:
                return '%d:%d:%d' %(lapsed_time.hour, lapsed_time.minute, lapsed_time.second)
            else:
                return 'NA'
        except Exception:  
            return 'NA'

    def get_ip(self):
        # IP information
        try:
            return self.json_response['endpoints'][0]['ipAddress']
        except Exception:
            return 'NA'

    def get_server_name(self): 
        # Server name information
        try:
            return self.json_response['endpoints'][0]['serverName']
        except Exception:
            return 'NA'

    def get_grade(self):
        # Grade information
        try:
            return self.json_response['endpoints'][0]['grade']
        except Exception:
            return 'NA'

    def get_sgrade(self):
        # Grade information ignoring trust issues
        try:
            return self.json_response['endpoints'][0]['gradeTrustIgnored']
        except Exception:
            return 'NA'

    def get_grade_warnings(self):
        # hasWarnings - if this endpoint has warnings that might affect the score (e.g., get A- instead of A).
        try:
            return self.json_response['endpoints'][0]['hasWarnings']
        except Exception:
            return 'NA'

    def get_grade_exceptional(self):
        # isExceptional - this flag will be raised when an exceptional configuration is encountered. The SSL Labs test will give such sites an A+.
        try:
            return self.json_response['endpoints'][0]['isExceptional']
        except Exception:
            return 'NA'

    def get_domain_delegation(self):
        #delegation - indicates domain name delegation with and without the www prefix 
        try:
            prefixed_access = self.json_response['endpoints'][0]['delegation']
            if self._bit_set(prefixed_access,0):
                return "non-prefixed access"
            elif self._bit_set(prefixed_access,1):
                return "prefixed access"
        except Exception:
            return 'NA'

    def get_server_signature(self):
        # server signature 
        try:
            server_signature = self.json_response['endpoints'][0]['details']['serverSignature']
            return server_signature
        except Exception:
            return 'NA'

    def get_key_size(self):
        # key size 
        try:
            key_size = self.json_response['endpoints'][0]['details']['key']['size']
            return key_size
        except Exception:
            return 'NA'

    def get_key_strength(self):
       # key strength
        try:
            key_strength = self.json_response['endpoints'][0]['details']['key']['strength']
            return key_strength
        except Exception:
            return 'NA'

    def get_key_algorithm(self):
        # key algorithm
        try:
            key_algorithm = self.json_response['endpoints'][0]['details']['key']['strength']
            return key_algorithm
        except Exception:
            return 'NA'

    def get_beast_status(self):
        # beast vulnerability status 
        # Ref - https://docs.secureauth.com/pages/viewpage.action?pageId=14778519
        try:
            if self.json_response['endpoints'][0]['details']['vulnBeast']:
                return "Y"
            else:
                return "N"
        except Exception:
            return 'NA'

    def get_session_resumption(self):
        # session resumption 
        try:
            session_resumption = self.json_response['endpoints'][0]['details']['sessionResumption']
            if session_resumption == 2:
                return "Supported"
            else: 
                return "Not supported"
        except Exception:
            return 'NA'

    def get_npn_protocol_support(self):
        # support for NPN protocols
        # Ref - https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html 
        try:
            if self.json_response['endpoints'][0]['details']['supportsNpn']:
                return "Y"
            else:
                return "N"
        except Exception:  
            return "NA"

    def get_session_tickets_support(self):
        # support for session tickets
        # Ref - https://blog.filippo.io/we-need-to-talk-about-session-tickets/
        try:
            session_tickets =  self.json_response['endpoints'][0]['details']['sessionTickets']
            if self._bit_set(session_tickets,0):
                return "Y"
            else:
                return "N"
        except Exception:  
            return "NA"

    def get_ocsp_stapling_support(self):
        # support for OCSP stapling
        # Ref - https://www.thawte.com/assets/documents/whitepaper/ocsp-stapling.pdf
        try:
            if self.json_response['endpoints'][0]['details']['ocspStapling']:
                return "Y"
            else:
                return "N"
        except Exception:  
            return "NA"

    def get_sni_support(self):
        # support for SNI
        # Ref - https://support.comodo.com/index.php?/Knowledgebase/Article/View/1120/38/what-is-sni-and-how-it-works
        try:
            if self.json_response['endpoints'][0]['details']['sniRequired']:
                return "Y"
            else:
                return "N"
        except Exception:  
            return "NA"

    def get_forward_secrecy_support(self):
        # support for forward secrecy
        # Ref - https://www.digicert.com/ssl-support/ssl-enabling-perfect-forward-secrecy.htm
        try:
            forward_secrecy =  self.json_response['endpoints'][0]['details']['forwardSecrecy']
            if self._bit_set(session_tickets,0):
                return "Y"
            else:
                return "N"
        except Exception:  
            return "NA"

    def get_certificate_sct_support(self):
        # certificate transparency availability
        try:
            certificate_sct_support =  self.json_response['endpoints'][0]['details']['hasSct']
            if self._bit_set(certificate_sct_support,0) or self._bit_set(certificate_sct_support,1) \
            or self._bit_set(certificate_sct_support,2) :
                return "Y"
            else:
                return "N"
        except Exception:  
            return "NA"

    def get_heartbleed_status(self):
        # heartbleed attack
        # Ref - http://heartbleed.com
        # https://www.us-cert.gov/ncas/alerts/TA14-098A  
        try:
            if self.json_response['endpoints'][0]['details']['heartbleed']:
                return "Y"
            else:
                return "N"
        except Exception:  
            return "NA"

    def get_crime_status(self):
        # crime vulnerability
        # Ref - https://www.acunetix.com/vulnerabilities/web/crime-ssl-tls-attack
        try: 
            if self.json_response['endpoints'][0]['details']['compressionMethods']!= 0 and \
             self.json_response['endpoints'][0]['details']['supportsNpn'] == False:
                return "Y"
            else:
                return "N"
        except Exception:
            return "NA"

    def get_freak_status(self):
        # freak vulnerability status 
        # Ref - https://www.digicert.com/blog/freak-attack-need-know/
        try:
            if self.json_response['endpoints'][0]['details']['freak']:
                return "Y"
            else:
                return "N"
        except Exception:
            return 'NA'

    def get_logjam_status(self):
        # logjam vulnerability status
        # Ref - https://blog.cloudflare.com/logjam-the-latest-tls-vulnerability-explained/
        try:
            if self.json_response['endpoints'][0]['details']['logjam']:
                return "Y"
            else:
                return "N"
        except Exception:
            return 'NA'

    def get_poodle_status(self):
        # poodle vulnerability status
        try:
            poodle_response = self.json_response['endpoints'][0]['details']['poodle']
            if poodle_response:
                return "Y"
            else:
                return "N"
        except Exception:
            return 'NA'

    def get_poodle_tls_status(self):
        # poodle TLS vulnerability status
        # Ref - https://www.openssl.org/~bodo/ssl-poodle.pdf  
        try:
            poodle_response = self.json_response['endpoints'][0]['details']['poodleTls']

            if poodle_response == 2:
                return "Y"
            elif poodle_response == 1:
                return "N"
            else: 
                return 'NA'

        except Exception:
            return 'NA'

    def get_insecure_client_renegotiation_status(self):
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
            renegotation_response = self.json_response['endpoints'][0]['details']['renegSupport']
            if self._bit_set(renegotation_response,0):
                return "Y"
            else:
                return "N"
        except Exception:
            return 'NA'

    def get_secure_renegotiation_status(self):        
        #secure renegotiation support
        try:
            renegotation_response = self.json_response['endpoints'][0]['details']['renegSupport']
            if self._bit_set(renegotation_response,1):
                return "Y"
            else:
                return "N"
        except Exception:
            return 'NA'

    def get_secure_client_renegotiation_status(self):
        #secure client renegotiation support
        try:
            renegotation_response = self.json_response['endpoints'][0]['details']['renegSupport']
            if self._bit_set(renegotation_response,2):
                return "Y"
            else:
                return "N"
        except Exception:
            return 'NA'

    def get_secure_renegotiation_server_support(self):
        #secure renegotiation -server support
        try:
            renegotation_response = self.json_response['endpoints'][0]['details']['renegSupport']
            if self._bit_set(renegotation_response,3):
                return "Y"
            else:
                return "N"
        except Exception:
            return 'NA'

    def get_opensslccs_status(self):
        # OpenSslCcs 
        # Ref - https://access.redhat.com/articles/904433
        # openSslCcs - results of the CVE-2014-0224 test:
        #    -1 - test failed
        #     0 - unknown
        #     1 - not vulnerable
        #     2 - possibly vulnerable, but not exploitable
        #     3 - vulnerable and exploitable
        try:
            opensslccs_response = self.json_response['endpoints'][0]['details']['openSslCcs']
            if opensslccs_response == 1:
                return "N"
            elif opensslccs_response == 2 or opensslccs_response == 3 :
                return "Y"
            else: # ignore test failed, unknown cases
                return "NA"
        except Exception:
            return 'NA'

    def get_openssl_luckyminus_status(self):        
        # openSSLLuckyMinus20
        # Ref - https://blog.cloudflare.com/yet-another-padding-oracle-in-openssl-cbc-ciphersuites/
        # openSSLLuckyMinus20 - results of the CVE-2016-2107 test:
        #   -1 - test failed
        #    0 - unknown
        #    1 - not vulnerable
        #    2 - vulnerable and insecure
        try:
            openssl_lucky_minus_response = self.json_response['endpoints'][0]['details']['openSSLLuckyMinus20']
            if openssl_lucky_minus_response == 1:
                return "N"
            elif openssl_lucky_minus_response == 2 :
                return "Y"
            else: # ignore test failed, unknown cases
                return "NA"
        except Exception:
            return 'NA'

    def get_rc4_status(self):
        # Support for RC4 cipher
        try:
            rc4_support = self.json_response['endpoints'][0]['details']['supportsRc4'] 
            if rc4_support:
                return 'Y'
            else: 
                return 'N'
        except Exception:
            return 'NA'

    def get_rc4_only_status(self):
        # Support for RC4 only cipher
        try:
            rc4_only = self.json_response['endpoints'][0]['details']['rc4Only'] 
            if rc4_only:
                return 'Y'
            else: 
                return 'N'
        except Exception:
            return 'NA'

    def get_weak_signature_algorithm_status(self):
        # Signature algorithm should not be weak like SHA1
        try:
            sig_algorithm = self.json_response['endpoints'][0]['details']['cert']['sigAlg'] 
            if "SHA1" in sig_algorithm:
                return 'Y'
            else: 
                return 'N'
        except Exception:
            return 'NA'

    def get_certificate_subject(self):
        # certificate subject
        try:
            cert_subject = self.json_response['endpoints'][0]['details']['cert']['subject'] 
            return cert_subject
        except Exception:
            return 'NA'

    def get_certificate_common_names(self):
        # certificate common names
        try:
            c_name = self.json_response['endpoints'][0]['details']['cert']['commonNames'] 
            domain_results['cert_common_names'] = c_name
        except Exception:
            self.results['cert_common_names'] = 'NA'

    def get_certificate_alternate_names(self):
        # certificate alternate names
        try:
            c_name = self.json_response['endpoints'][0]['details']['cert']['altNames'] 
            return c_name
        except Exception:
            return 'NA'

    def get_certificate_validity(self):
        # certificate validity
        try:
            valid_date = self.json_response['endpoints'][0]['details']['cert']['notAfter'] 
            return "%s:%s" % (valid_date,self._timestamp_to_date(valid_date))
        except Exception:
            return 'NA'

    def get_certificate_issuer_subject(self):
        # certificate issuer subject
        try:
            issuer_subject = self.json_response['endpoints'][0]['details']['cert']['issuerSubject'] 
            return issuer_subject
        except Exception:
            return 'NA'

    def get_certificate_issuer_label(self): 
        # certificate issuer label
        try:
            issuer_label = self.json_response['endpoints'][0]['details']['cert']['issuerLabel'] 
            return issuer_label
        except Exception:
            return 'NA'

    def get_certificate_algorithm(self):
        # certificate signature algorithm
        try:
            cert_signature_algo = self.json_response['endpoints'][0]['details']['cert']['sigAlg'] 
            return cert_signature_algo
        except Exception:
            return 'NA'

    def get_certificate_revocation_status(self):
        # certificate revocation status
        try:
            cert_revocation_status = self.json_response['endpoints'][0]['details']['cert']['revocationStatus'] 
            if cert_revocvation_status == 0:
                return "Not checked"
            elif cert_revocvation_status == 1:
                return "Revoked"
            elif cert_revocvation_status == 2:
                return "Not revoked"
            elif cert_revocvation_status == 3:
                return "Revokation error"
            elif cert_revocvation_status == 4:
                return "Revokation information absent"

        except Exception:
            return 'NA'

    def get_certificate_extended_validation_status(self):
        # certificate - extended validation support
        try:
            cert_extended_validation = self.json_response['endpoints'][0]['details']['cert']['validationType'] 
            if cert_extended_validation == 'E':
                return "Y"
            else:
                return "N"
        except Exception:
            return 'NA'

    def get_cipher_suites(self):
         # cipher suites supported
        try:
            cipher_suites = self.json_response['endpoints'][0]['details']['suites']
            cipher_list = list()
            for item in cipher_suites['list']:
                cipher_dict = dict()
                cipher_dict.update({ 'name' : item['name'] })
                cipher_dict.update({ 'cipher_strength' : item['cipherStrength'] })
                cipher_list.append(cipher_dict)
            return cipher_list
        except Exception:
            return 'NA'

    def get_hsts_status(self):
         # hsts policy status
        try:
            hsts_policy = self.json_response['endpoints'][0]['details']['hstsPolicy']
            return hsts_policy['status']
        except Exception:
            return 'NA'
        
