#!/usr/bin/env python
from flask import Flask,render_template,request,url_for,abort,redirect,flash
import requests
import json
import datetime
from forms import SearchForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['CSRF_SESSION_KEY'] = 'secret'
app.debug = True

@app.route('/')
def main():
    #return "<h1> Welcome to SSL LABS API - SSL testing </h1>"
    return render_template("dashboard.html")

@app.route('/elastic_read')
def el_read():
    url = 'http://localhost:9200/vulnerabilities/ssllabs/_search'
    query = {
            "query": {
                "match_all" : {}
            }
    }
    response = requests.post(url,data=json.dumps(query))
    data = response.json()
    table_entries = list()
    table_entry = dict()
    for hit in data['hits']['hits']:
        table_entry = dict()
        print hit['_id']
        table_entry['id'] = hit['_id']
        entry_details = hit['_source']
        #pprint(entry_details)
        #print "ID - %s" % hit['_id']
        if entry_details['ts']:
            table_entry['scan_time'] = datetime.datetime.strptime(entry_details['ts'],'%Y-%m-%dT%H:%M:%S.%f')
        else:
            table_entry['scan_time'] = ''
        table_entry['server'] = entry_details['server_name']
        table_entry['assessment_time'] = entry_details['assessment_time(hh:mm:ss)']
        #table_entry['id'] = entry_details['_id']
        table_entries.append(table_entry)
    return render_template("el_response.html",elastic_results=table_entries)

@app.route('/record',methods=['GET'])
def el_record():
    #print request.args.get('elastic_id')
    #return "Hello"
    record_id = request.args.get('elastic_id')    
    url = 'http://localhost:9200/vulnerabilities/ssllabs/_search'
    query = {
            "query": {
                "ids": {
                    "values":[record_id]
                }
            }
    }
    response = requests.post(url,data=json.dumps(query))
    data = response.json()

    if not data['hits']['hits']:
        return("No SSL scan record found!")
	
    data_record = data['hits']['hits'][0]['_source']
    data_record['assessment_time']=data_record['assessment_time(hh:mm:ss)']
    #print data
    return render_template("ssl_report.html",elastic_report=data_record)

@app.route('/search', methods=['GET','POST'])
def search():
    form = SearchForm(request.form)
    if form.validate_on_submit():
        search_server = request.form['server'].strip()
        search_date = request.form['dt']
        print search_server, search_date
        return redirect(url_for('search_fields',server=search_server,scan_date=search_date))
        #return("Form submission success!") 
    return render_template('search_form.html', form=form)


@app.route('/search_fields', methods=['GET'])
def search_fields():
    #print request.args.get('server')
    #print request.args.get('scan_date')
    server_name = request.args.get('server')
    scan_date = request.args.get('scan_date')
    url ='http://localhost:9200/vulnerabilities/ssllabs/_search'
    #query = {
    #    "query": {
    #        "query_string" : {
    #	        "query": "(host:%s*) AND (ts:%s)"%(server_name,scan_date)
    #	    }
    #	}
    #}

    query = {
       "query": {
	    "bool": {
			"must":{
			"query_string" : {"query": "host:%s*"%server_name }
			},
			"filter":{
			"range": {
				"ts": {
					"gte": "%s"%scan_date
				}
			}
			}
		}
	}

    }
    response = requests.post(url, data = json.dumps(query))
    data = response.json()
    #from pprint import pprint
    #pprint(data)
    #return "Sucess"
    # return if no data
    if not data['hits']['hits']:
        return("No SSL scan reports found!")
	
    table_entries = list()
    table_entry = dict()
    for hit in data['hits']['hits']:
        table_entry = dict()
        print hit['_id']
        table_entry['id'] = hit['_id']
        entry_details = hit['_source']
        #pprint(entry_details)
        #print "ID - %s" % hit['_id']
        if entry_details['ts']:
            table_entry['scan_time'] = datetime.datetime.strptime(entry_details['ts'],'%Y-%m-%dT%H:%M:%S.%f')
        else:
            table_entry['scan_time'] = ''
        table_entry['server'] = entry_details['server_name']
        table_entry['assessment_time'] = entry_details['assessment_time(hh:mm:ss)']
        #table_entry['id'] = entry_details['_id']
        table_entries.append(table_entry)
    return render_template("el_response.html",elastic_results=table_entries)

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0')
