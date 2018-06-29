#!/usr/bin/env python
from __future__ import unicode_literals
import logging
import sys
import argparse
import yaml
from utils.ssllabs_api import SSLLabsAPI
from utils.parse_report import Parse_SSLLabs
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from utils.manage_elasticsearch import Manage_Elasticsearch
from datetime import datetime, timedelta

import ast
from pprint import pprint

"""
    This script uses SSL Labs API to check security status of your SSL server and you can be used to improve
    security configuration of server(s) in the organization.
"""

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

def read_config(yaml_file):
    with open(yaml_file, 'r') as f:
        configuration_data = yaml.load(f)
    return configuration_data

def update_elasticsearch(elastic_config,domain):
    bulk_records = 500
    try:
        #elasticsearch index name
        es_index = elastic_config['index']
        es_doctype = elastic_config['doc_type']
        es_host = elastic_config['host']
        es_port = elastic_config['port']

        # create elasticsearch instance
        el_instance = Manage_Elasticsearch(es_host,
                                   es_port,
                                   es_index,
                                   es_doctype,bulk_records)
        es_health = el_instance.check_health()
        if not es_health:
            logger.info("Failed to connect to Elasticsearch server." 
                        " Kindly re-check Elasticsearch settings"
                        " and then try again")
            sys.exit(1) 

        # check if elasticsearch index exists. If not, create a new elastic index.
        index_present = el_instance.index_exists(es_index)
        if not index_present: 
            response = el_instance.create_index(es_index)

        # update ssllabs-api results to elasticsearch
        el_instance.update_dict(data)
        logger.info("SSL Labs API report for domain %s is written to elasticsearch successfully." %domain)
    except Exception,e:
        logger.error("Error while updating ssl report in elasticsearch database - %s" %e.message,exc_info=True)


def cmd_arguments():

    try:
        parser = argparse.ArgumentParser("This script uses SSL Labs API to check state of various SSL" 
                 "settings of HTTPS server(s) facing the internet and can be used to their improve security configuration")

        parser.add_argument('--config', required=True, help='Please specify full path of configuration file',dest='config')
        args = parser.parse_args()
        return args
    except Exception as exc:
        logger.error("Error while getting command line arguments - %s" %exc.message,exc_info=True)


if __name__ == "__main__":
    try:
        cmd_args = cmd_arguments()
        if cmd_args.config: 
            config = read_config(cmd_args.config) 
            logger.debug("{}".format(config)) 
            # setup proxy during initialization of SSLLabs API class
            sslapi_instance = SSLLabsAPI(config['general']['use_proxy'],config['general']['proxy_auth_type'], config['proxy']['timeout'],
                                         config['proxy']['host'],config['proxy']['port'],
                                         config['proxy']['user'],config['proxy']['password']) 

            for domain in config['https_servers']:
                domain = domain.replace('https://','').replace('http://','')
                #domain_results = sslapi_instance.new_scan(domain,'off','on','done','off','on',24)
                domain_results = sslapi_instance.new_scan(domain)
                #domain_results = sslapi_instance.cache_results(domain) 
                logger.debug("ssl report for domain %s - %s" %(domain, domain_results))
                # parsing ssl report
                #with open('google.json','r') as f:
                #    read_json = f.read()
                #    # convert string to dict using ast.literal_eval
                #    json_result = ast.literal_eval(read_json)

                parse_report = Parse_SSLLabs(domain_results)
                # get parsed report
                parsed_report = parse_report.get_results()
                # update report in elasticsearch
                update_elasticsearch(config['elastic'],domain)  
            sys.exit(1)

    except Exception,e:
        logger.error("Error while running the script - %s" % e.message,exc_info=True)
