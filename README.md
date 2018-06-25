### SSLLABS-API
Uses SSL LABS API to generate ssl reports for https site(s) and sends them to ELK stack for further analysis

It is imperative that we keep a watch on security anomalies reported in ssl reports of Qualysis SSL Labs. Using this script, it is possible to scan a single site or multiple site(s) for any SSL vulnerabilties and apply prompt corrective action.

#### Why
Qualysis SSL Labs allows you to test your ssl configuration using a web interface and it generates a nice HTML report for vulnerable SSL settings. Most of the people use them and take prompt corrective actions. However, it is cumbersome to manaage and track changes in SSL configuration for server(s) in any organization over a longer period of time. Qualysis also offers a free SSL API service which you can make use of to generate SSL reports in a programmatic way. This python script uses SSL LABS API to generate ssl reports and sends it to Elasticsearch database for storage. The reports can be retrieved on demand later from Elastic database. This makes it easy to track changes in server/server-group ssl security settings over a period of time. It also makes it easy to pin-point the state of any ssl related security settings quickly and sort out ssl related confiuration issues quickly.

Basically, the report generation and its integration is carried out in the following steps:

### ssl_report
Generate a ssl report using Qualysis SSL LABS API and you can use it to scan a single SSL site or multiple site(s) for SSL vulnerabilties.

```
$ python ssllabsapi.py --domain google.com > google.json
```

OR

```
python ssllabsapi_multiple_sites.py --config settings.yaml > google.json
```

Typically, you specify multiple site(s) as a part of settings.yaml. Also, do not forget to enter full path. Otherwise, you will encounter errors!

### parse_report

It uses google.json generated using 'ssl_report' action.

Before using google.json, please remove the first line consisting of 'DEBUG:' using vim or any other editor.
```
$ python parse_ssllabs_results.py 
```
It will print a dictioary of results using Qualysis SSL report.

### elasticsearch integration
 The json generated is sent to Elasticsearch database for storage.


