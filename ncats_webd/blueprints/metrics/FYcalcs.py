#!/usr/bin/env python

'''Generate data for end of fiscal year CyHy reporting.

Usage:
  FYcalcs.py [--section SECTION] [STARTDATE] [ENDDATE]
  FYcalcs.py (-h | --help)
  FYcalcs.py --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.

'''

import sys
import os
from docopt import docopt
import netaddr
import datetime
import time
import json
from cyhy.db import database
from cyhy.util import util
from cyhy.core.common import REPORT_TYPE, AGENCY_TYPE

# See categorize_orgs() for how these dicts are populated
ALL_ORGS_BY_TYPE = dict()
ALL_STAKEHOLDERS_BY_TYPE = dict()

def vuln_ticket_counts(FY_START, FY_END, db, severity=0):
    #TODO: Modify print statements to use format() named parameters
    if severity == 0:
        opened_before_and_still_open = db.TicketDoc.find({'false_positive':False, 'time_opened':{'$lt':FY_START}, 'open':True}).count()
        opened_before_and_closed_during = db.TicketDoc.find({'false_positive':False, 'time_opened':{'$lt':FY_START}, 'time_closed':{'$gte':FY_START, '$lt':FY_END}}).count()
        opened_during_and_still_open = db.TicketDoc.find({'false_positive':False, 'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'open':True}).count()
        opened_during_and_closed_during = db.TicketDoc.find({'false_positive':False, 'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'time_closed':{'$lt':FY_END}}).count()
        opened_during_and_closed_after = db.TicketDoc.find({'false_positive':False, 'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'time_closed':{'$gte':FY_END}}).count()
        fp_before = db.TicketDoc.find({'false_positive':True, 'time_opened':{'$lt':FY_START}}).count()
        fp_during = db.TicketDoc.find({'false_positive':True, 'time_opened':{'$gte':FY_START, '$lt':FY_END}}).count()
        fp_after = db.TicketDoc.find({'false_positive':True, 'time_opened':{'$gte':FY_END}}).count()

        vulnerable_host_count = len(db.TicketDoc.find({'$or':[
            {'time_opened':{'$lt':FY_START}, 'open':True},
            {'time_opened':{'$lt':FY_START}, 'time_closed':{'$gte':FY_START, '$lt':FY_END}},
            {'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'open':True},
            {'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'time_closed':{'$lt':FY_END}},
            {'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'time_closed':{'$gte':FY_END}}]}).distinct('ip_int'))
    else:
        opened_before_and_still_open = db.TicketDoc.find({'false_positive':False, 'time_opened':{'$lt':FY_START}, 'open':True, 'details.severity':severity}).count()
        opened_before_and_closed_during = db.TicketDoc.find({'false_positive':False, 'time_opened':{'$lt':FY_START}, 'time_closed':{'$gte':FY_START, '$lt':FY_END}, 'details.severity':severity}).count()
        opened_during_and_still_open = db.TicketDoc.find({'false_positive':False, 'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'open':True, 'details.severity':severity}).count()
        opened_during_and_closed_during = db.TicketDoc.find({'false_positive':False, 'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'time_closed':{'$lt':FY_END}, 'details.severity':severity}).count()
        opened_during_and_closed_after = db.TicketDoc.find({'false_positive':False, 'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'time_closed':{'$gte':FY_END}, 'details.severity':severity}).count()
        fp_before = db.TicketDoc.find({'false_positive':True, 'time_opened':{'$lt':FY_START}, 'details.severity':severity}).count()
        fp_during = db.TicketDoc.find({'false_positive':True, 'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'details.severity':severity}).count()
        fp_after = db.TicketDoc.find({'false_positive':True, 'time_opened':{'$gte':FY_END}, 'details.severity':severity}).count()

        vulnerable_host_count = len(db.TicketDoc.find({'$or':[
            {'time_opened':{'$lt':FY_START}, 'open':True, 'details.severity':severity},
            {'time_opened':{'$lt':FY_START}, 'time_closed':{'$gte':FY_START, '$lt':FY_END}, 'details.severity':severity},
            {'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'open':True, 'details.severity':severity},
            {'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'time_closed':{'$lt':FY_END}, 'details.severity':severity},
            {'time_opened':{'$gte':FY_START, '$lt':FY_END}, 'time_closed':{'$gte':FY_END}, 'details.severity':severity}]}).distinct('ip_int'))

    sev_level = ''
    if severity == 1:
        sev_level = 'Low '
    elif severity == 2:
        sev_level = 'Medium '
    elif severity == 3:
        sev_level = 'High '
    elif severity == 4:
        sev_level = 'Critical '

    output = {'severity_level':sev_level}
    output['opened_before_and_still_open'] = "{:,d}".format(opened_before_and_still_open)
    output['opened_before_and_closed_during'] = "{:,d}".format(opened_before_and_closed_during)
    output['opened_during_and_still_open'] = "{:,d}".format(opened_during_and_still_open)
    output['opened_during_and_closed_during'] = "{:,d}".format(opened_during_and_closed_during)
    output['opened_during_and_closed_after'] = "{:,d}".format(opened_during_and_closed_after)
    output['fp_before'] = "{:,d}".format(fp_before)
    output['fp_during'] = "{:,d}".format(fp_during)
    output['fp_after'] = "{:,d}".format(fp_after)
    total_vulns = opened_before_and_still_open + opened_before_and_closed_during + opened_during_and_still_open + opened_during_and_closed_during + opened_during_and_closed_after
    output['total_vulns'] = "{:,d}".format(total_vulns)
    output['vulnerable_host_count'] = "{:,d}".format(vulnerable_host_count)
    if (float(vulnerable_host_count > 0)):
        output['avg_vulns_per_vulnerable_host'] = "{:.2f}".format(total_vulns / float(vulnerable_host_count))
    else:
        output['avg_vulns_per_vulnerable_host'] = "0.00"

    output['description'] = ("""---
Data Source: tickets collection
Methodology: Divide tickets into timeframes by time_opened, time_closed, and whether or not the ticket is still open. False positive tickets not included.
Notes:
* The last bucket (tix opened between {start date} and {end date}, and closed after {end date}) accounts for tickets that get closed between the {end date} and when this report is run.
---""")
    return output

def print_vuln_ticket_counts(FY_START, FY_END, obj):
    print '\n{:}Vulnerability tickets opened before {:} and still open now: {:}'.format(obj['severity_level'], FY_START, obj['opened_before_and_still_open'])
    print '{:}Vulnerability tickets opened before {:} and closed by {:}: {:}'.format(obj['severity_level'], FY_START, FY_END, obj['opened_before_and_closed_during'])
    print '{:}Vulnerability tickets opened between {:} and {:} and still open now: {:}'.format(obj['severity_level'], FY_START, FY_END, obj['opened_during_and_still_open'])
    print '{:}Vulnerability tickets opened after {:} and closed by {:}: {:}'.format(obj['severity_level'], FY_START, FY_END, obj['opened_during_and_closed_during'])
    print '{:}Vulnerability tickets opened between {:} and {:}, and closed after {:}: {:}'.format(obj['severity_level'], FY_START, FY_END, FY_END, obj['opened_during_and_closed_after'])
    print 'False positives tickets opened before {:}: {:}'.format(FY_START, obj['fp_before'])
    print 'False positives tickets opened between {:} and {:}: {:}'.format(FY_START, FY_END, obj['fp_during'])
    print 'False positives tickets opened after {:}: {:}'.format(FY_END, obj['fp_after'])
    print '-----------------------------------------------------'
    print 'Total {:}vulnerability tickets open at any point between {:} and {:}: {:}'.format(obj['severity_level'], FY_START, FY_END, obj['total_vulns'])
    print 'Total vulnerable hosts for tickets above: {:}'.format(obj['vulnerable_host_count'])
    print 'Average vulnerabilities per vulnerable host: {:}'.format(obj['avg_vulns_per_vulnerable_host'])
    print obj['description']

# top occurring vulnerabilities -> % by breakdown and total occurrences
def top_vulns(FY_START, FY_END, db, severity=0):
    # 1 = low, 2 = medium, 3 = high, 4 = critical

    if severity == 0:
        pipeline = [
        {'$match': {'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}}},
        {'$group': {'_id':{'source_id':'$source_id', 'details.name':'$details.name'}, 'count':{'$sum':1}}},
        {'$sort': {'count':-1}}
        ]
    else:
        pipeline = [
        {'$match': {'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'details.severity':severity}},
        {'$group': {'_id':{'source_id':'$source_id', 'details.name':'$details.name'}, 'count':{'$sum':1}}},
        {'$sort': {'count':-1}}
        ]
    result = db.tickets.aggregate(pipeline, cursor={})
    total = 0
    lvl = ''
    if severity == 1:
        lvl = 'Low '
    elif severity == 2:
        lvl = 'Medium '
    elif severity == 3:
        lvl = 'High '
    elif severity == 4:
        lvl = 'Critical '
    for j in range(0, len(result['result'])):
        total = total + int(result['result'][j]['count'])

    output = {'level':lvl}
    output['total'] = "{:,d}".format(total)
    mylist = []

    for i in range(0,(10 if len(result['result']) > 10 else len(result['result']))):
        # Get most recent plugin_name associated with each plugin_id (names can change, but IDs are forever... we hope)
        #Vuln = db.vuln_scans.find({"plugin_id":result['result'][i]['_id']['source_id']},
        #                          {"_id":0, "plugin_name":1}).sort([('$natural',-1)]).limit(1)

        #if Vuln.count() > 0:
        #    Vuln = Vuln.next().get('plugin_name')
        #else:
        Vuln = result['result'][i]['_id']['details.name']

        count = result['result'][i]['count']
        myarg = {'vuln': Vuln,
                 'count': "{:,d}".format(count),
                 'pct': round((float(count)/total)*100, 1)
                 }
        mylist.append(myarg)

    output['data'] = mylist
    output['description'] = ("""---
Data Sources:
* tickets collection - for vulnerability counts
* vuln_scans collection - for latest vulnerability names
Methodology: Group vulns by source_id, then count the number of occurrences of each source_id. False positive tickets not included.
Notes:
* The plugin_name associated with a plugin_id can also change over time, so output is the most-recent plugin_name tied to each plugin_id.
---""")

    return output

def print_top_vulns(FY_START, FY_END, obj):
    print '\nTop 10 {:}Ticketed Vulnerabilities\nTotal {:}Vulnerability Tickets Opened: {:}\n========================'.format(obj['level'], obj['level'], obj['total'])
    for item in obj['data']:
        #print item['vuln'] + ': ' + item['count'] + ' (' + str(item['pct']) + '%)'
        print "{:}: {:} ({:}%)".format(item['vuln'], item['count'], item['pct'])
    print obj['description']

def top_OS(FY_START, FY_END, db):
    pipeline = [
    {'$match': {'time': {'$gte':FY_START, '$lt':FY_END}}},
    {'$group': {'_id':{'type':'$name','ip':'$ip_int'}}},
    {'$group': {'_id':{'type':'$_id.type'}, 'count':{'$sum':1}}},
    {'$sort': {'count':-1}}
    ]
    result = db.host_scans.aggregate(pipeline, allowDiskUse=True, cursor={})
    total = 0
    for j in range(0, len(result['result'])):
        total = total + int(result['result'][j]['count'])

    output = {'total':"{:,d}".format(total)}
    mylist = []

    for i in range(0,10):
        OStype = result['result'][i]['_id']['type']
        count = result['result'][i]['count']

        #output.append([OStype, "{:,d}".format(count), round((float(count)/total)*100, 1)])

        myarg = {'OS': OStype,
                 'count': "{:,d}".format(count),
                 'pct': round((float(count)/total)*100, 1)
                 }
        mylist.append(myarg)

    output['data'] = mylist
    output['description'] = ("""---
Data Source: host_scans collection
Methodology: Group hosts by (OS) name and ip, then count the number of occurrences of each OS name.
Notes:
* A host will be counted more than once if it was upgraded to a different OS during the reporting window.
* A host will be counted more than once if network/host conditions change in a way that nmap now thinks there's a different OS on the host.
* An 'unknown' OS on a scanned host is a good thing, from a security perspective.
---""")

    return output

def print_top_OS(FY_START, FY_END, obj):
    print '\nTop 10 Operating System Fingerprints\nTotal Fingerprinted Hosts: {:} \n========================'.format(obj['total'])
    for item in obj['data']:
        #print item['OS'] + ': ' + item['count'] + ' (' + str(item['pct']) + '%)'
        print "{:}: {:} ({:}%)".format(item['OS'], item['count'], item['pct'])
    print obj['description']

def top_vuln_services(FY_START, FY_END, db):
    pipeline = [
    {'$match': {'time': {'$gte':FY_START, '$lt':FY_END}}},
    {'$group': {'_id':{'service':'$service','port':'$port','ip':'$ip_int'}}},
    {'$group': {'_id':{'service':'$_id.service'}, 'count':{'$sum':1}}},
    {'$sort': {'count':-1}}
    ]
    result = db.vuln_scans.aggregate(pipeline, cursor={})
    total = 0
    for j in range(0, len(result['result'])):
        total = total + int(result['result'][j]['count'])
    #output =["{:,d}".format(total)]
    output = {'total':"{:,d}".format(total)}
    mylist = []

    if len(result['result']) >= 10:
        result_range = range(0, 10)
    else:
        result_range = range(0, len(result['result']))
    for i in result_range:
        service = result['result'][i]['_id']['service']
        count = result['result'][i]['count']
        #output.append([service, "{:,d}".format(count), round((float(count)/total)*100, 1)])
        #print '{:}: {:} ({:}%)'.format(output[i+1][0], output[i+1][1], output[i+1][2])
        myarg = {'service': service,
                 'count': "{:,d}".format(count),
                 'pct': round((float(count)/total)*100, 1)
                 }
        mylist.append(myarg)

    output['data'] = mylist
    output['description'] = ("""---
Data Source: vuln_scans collection
Methodology: Group vulns by service, port and IP, then count the number of occurrences of each service.
Notes:
* Group by IP to avoid re-counting a service that was detected on a host in multiple scans.
* Vulns can exist on multiple ports on the same host, so we include port in the grouping.
---""")

    return output

def print_top_vuln_services(FY_START, FY_END, obj):
    print '\nTop 10 Vulnerable Services\nTotal Vulnerable Services: {:}\n========================'.format(obj['total'])
    for item in obj['data']:
        #print item['service'] + ': ' + item['count'] + ' (' + str(item['pct']) + '%)'
        print "{:}: {:} ({:}%)".format(item['service'], item['count'], item['pct'])
    print obj['description']

def top_services(FY_START, FY_END, db):
    pipeline = [
    {'$match': {'time': {'$gte':FY_START, '$lt':FY_END}}},
    {'$group': {'_id':{'service': {'$ifNull':['$service.name','unknown']},'ip':'$ip_int','port':'$port'}}},
    {'$group': {'_id':{'service': '$_id.service'}, 'count':{'$sum':1}}},
    {'$sort': {'count':-1}}
    ]
    result = db.port_scans.aggregate(pipeline, allowDiskUse=True, cursor={})
    total = 0
    for j in range(0, len(result['result'])):
        total = total + int(result['result'][j]['count'])

    output = {'total':"{:,d}".format(total)}
    mylist = []
    for i in range(0,10):
        service = result['result'][i]['_id']['service']
        count = result['result'][i]['count']
        #output.append([service, "{:,d}".format(count), round((float(count)/total)*100, 1)])
        #print '{:}: {:} ({:}%)'.format(output[i+1][0], output[i+1][1], output[i+1][2])
        myarg = {'service': service,
                 'count': "{:,d}".format(count),
                 'pct': round((float(count)/total)*100, 1)
                 }
        mylist.append(myarg)

    output['data'] = mylist
    output['description'] = ("""---
Data Source: port_scans collection
Methodology: Group services by ip and port, then count the number of occurrences of each service name.
Notes:
* Group by IP to avoid re-counting a service that was detected on a host in multiple scans.
* Vulns can exist on multiple ports on the same host, so we include port in the grouping.
* If a service name cannot be identified, it is reported as 'unknown'.
---""")

    return output

def print_top_services(FY_START, FY_END, obj):
    print '\nTop 10 Service Fingerprints\nTotal Fingerprinted Services: {:}\n========================'.format(obj['total'])
    for item in obj['data']:
        #print item['service'] + ': ' + item['count'] + ' (' + str(item['pct']) + '%)'
        print "{:}: {:} ({:}%)".format(item['service'], item['count'], item['pct'])
    print obj['description']

def num_orgs_scanned(FY_START, FY_END, db):
    total_orgs = db.SnapshotDoc.find({'last_change': {'$gte':FY_START, '$lt':FY_END}, 'owner':{'$in':ALL_STAKEHOLDERS_BY_TYPE['ALL']} }).distinct('owner')
    fed_orgs = db.SnapshotDoc.find({'last_change': {'$gte':FY_START, '$lt':FY_END}, 'owner':{'$in':ALL_STAKEHOLDERS_BY_TYPE[AGENCY_TYPE.FEDERAL]} }).distinct('owner')
    sltt_orgs = db.SnapshotDoc.find({'last_change': {'$gte':FY_START, '$lt':FY_END}, 'owner':{'$in':ALL_STAKEHOLDERS_BY_TYPE['SLTT']} }).distinct('owner')
    private_orgs = db.SnapshotDoc.find({'last_change': {'$gte':FY_START, '$lt':FY_END}, 'owner':{'$in':ALL_STAKEHOLDERS_BY_TYPE[AGENCY_TYPE.PRIVATE]} }).distinct('owner')

    output = {
        'total_orgs':len(total_orgs),
        'fed_orgs':len(fed_orgs),
        'sltt_orgs':len(sltt_orgs),
        'private_orgs':len(private_orgs)
    }

    if (len(total_orgs) > 0):
        output['fed_orgs_pct'] = round((float(len(fed_orgs)) / len(total_orgs))*100, 1)
        output['sltt_orgs_pct'] = round((float(len(sltt_orgs)) / len(total_orgs))*100, 1)
        output['private_orgs_pct'] = round((float(len(private_orgs)) / len(total_orgs))*100, 1)
    else:
        output['fed_orgs_pct'] = 0
        output['sltt_orgs_pct'] = 0
        output['private_orgs_pct'] = 0

    output['description'] = ("""---
Data Source: snapshots collection
Methodology: Count the number of distinct snapshot owners (limited to stakeholder orgs).
---""")

    return output

def print_num_orgs_scanned(FY_START, FY_END, obj):
    print "\nTotal stakeholder organizations scanned: {:}".format(obj['total_orgs'])
    print "* FEDERAL stakeholder organizations: {:} ({:}%)".format(obj['fed_orgs'], obj['fed_orgs_pct'])
    print "* SLTT stakeholder organizations: {:} ({:}%)".format(obj['sltt_orgs'], obj['sltt_orgs_pct'])
    print "* PRIVATE stakeholder organizations: {:} ({:}%)".format(obj['private_orgs'], obj['private_orgs_pct'])
    print obj['description']

def num_addresses_hosts_scanned(FY_START, FY_END, db):
    ORGS_SCANNED_DURING_FY = db.snapshots.find({'last_change':{'$gte':FY_START, '$lt':FY_END}}).distinct('owner')

    total_uniq_ips = db.hosts.find({'owner':{'$in':ORGS_SCANNED_DURING_FY}, 'last_change':{'$gte':FY_START, '$lt':(FY_END + datetime.timedelta(30))}, 'state.reason':{'$ne':'new'}}).count()
    fed_uniq_ips = db.hosts.find({'owner':{'$in':list(set(ALL_ORGS_BY_TYPE[AGENCY_TYPE.FEDERAL]) & set(ORGS_SCANNED_DURING_FY))}, 'last_change':{'$gte':FY_START, '$lt':(FY_END + datetime.timedelta(30))}, 'state.reason':{'$ne':'new'}}).count()
    sltt_uniq_ips = db.hosts.find({'owner':{'$in':list(set(ALL_ORGS_BY_TYPE['SLTT']) & set(ORGS_SCANNED_DURING_FY))}, 'last_change':{'$gte':FY_START, '$lt':(FY_END + datetime.timedelta(30))}, 'state.reason':{'$ne':'new'}}).count()
    private_uniq_ips = db.hosts.find({'owner':{'$in':list(set(ALL_ORGS_BY_TYPE[AGENCY_TYPE.PRIVATE]) & set(ORGS_SCANNED_DURING_FY))}, 'last_change':{'$gte':FY_START, '$lt':(FY_END + datetime.timedelta(30))}, 'state.reason':{'$ne':'new'}}).count()

    output = {'total_addr': "{:,d}".format(total_uniq_ips)}
    if total_uniq_ips > 0:
        output['fed_addr_pct'] = round((float(fed_uniq_ips) / total_uniq_ips)*100,1)
        output['sltt_addr_pct'] = round((float(sltt_uniq_ips) / total_uniq_ips)*100,1)
        output['private_addr_pct'] = round((float(private_uniq_ips) / total_uniq_ips)*100,1)
    output['fed_addr'] = "{:,d}".format(fed_uniq_ips)
    output['sltt_addr'] = "{:,d}".format(sltt_uniq_ips)
    output['private_addr'] = "{:,d}".format(private_uniq_ips)
    output['description1'] = ("""---
Data Source: hosts collection\n
Methodology: Count the hosts with last_change in specified time period, excluding orgs that were not scanned during the specified time period (i.e. had no snapshots created) and excluding any hosts that haven't actually been scanned yet ('state.reason' == 'new').\n
Notes:\n
* This method is unreliable for addresses that were scanned longer than 30 days ago.\n
* Hack alert: 30 days is added to the end date of the specified time period to allow us to run this report after the end of the time period (since last_change will get updated by scans that happen after end of time period).\n
---""")

    result = dict()
    total_hosts_scanned = 0
    for (org_group, host_group) in [(ALL_ORGS_BY_TYPE[AGENCY_TYPE.FEDERAL], 'fed_hosts_scanned'), (ALL_ORGS_BY_TYPE['SLTT'], 'sltt_hosts_scanned'), (ALL_ORGS_BY_TYPE[AGENCY_TYPE.PRIVATE], 'private_hosts_scanned')]:
        pipeline = [
            { '$match': { 'owner': {'$in': org_group}, 'time': {'$gte':FY_START, '$lt':FY_END}}},
            { '$group': { '_id': {'ip_int':'$ip_int'}}},
            { '$group': { '_id':None, 'count': {'$sum':1}}}
        ]
        pipeline_result = db.host_scans.aggregate(pipeline, cursor={})['result']
        if len(pipeline_result) > 0:
            result[host_group] = pipeline_result[0]['count']
            total_hosts_scanned += result[host_group]
        else:
            result[host_group] = 0

    if total_hosts_scanned > 0:
        output['fed_hosts_scanned_pct'] = round((float((result['fed_hosts_scanned'])) / (total_hosts_scanned))*100,1)
        output['sltt_hosts_scanned_pct'] = round((float((result['sltt_hosts_scanned'])) / (total_hosts_scanned))*100,1)
        output['private_hosts_scanned_pct'] = round((float((result['private_hosts_scanned'])) / (total_hosts_scanned))*100,1)
    output['total_hosts_scanned'] = "{:,d}".format(result['fed_hosts_scanned'])
    output['fed_hosts_scanned'] = "{:,d}".format(result['fed_hosts_scanned'])
    output['sltt_hosts_scanned'] = "{:,d}".format(result['sltt_hosts_scanned'])
    output['private_hosts_scanned'] = "{:,d}".format(result['private_hosts_scanned'])
    output['description2'] = ("""---
Data Source: host_scans collection
Methodology: Count the distinct IPs (scanned hosts) with 'time' in specified time period.
Notes: None
---""")

    # total_hosts_active = db.HostDoc.find({'state.up':True, 'last_change': {'$gte':FY_START, '$lt':(FY_END + datetime.timedelta(30))}, 'owner': {'$nin': ORGS_SCANNED_DURING_FY}}).count()
    # fed_hosts_active = db.HostDoc.find({'state.up':True, 'last_change': {'$gte':FY_START, '$lt':(FY_END + datetime.timedelta(30))}, 'owner': {'$in': ALL_ORGS_BY_TYPE[AGENCY_TYPE.FEDERAL], '$nin': ORGS_SCANNED_DURING_FY}}).count()
    # sltt_hosts_active = db.HostDoc.find({'state.up':True, 'last_change': {'$gte':FY_START, '$lt':(FY_END + datetime.timedelta(30))}, 'owner': {'$in': SLTT, '$nin': ORGS_SCANNED_DURING_FY}}).count()
    # private_hosts_active = db.HostDoc.find({'state.up':True, 'last_change': {'$gte':FY_START, '$lt':(FY_END + datetime.timedelta(30))}, 'owner': {'$in': PRIVATE, '$nin': ORGS_SCANNED_DURING_FY}}).count()

    # output['total_hosts_active'] = "{:,d}".format(total_hosts_active)
    # output['fed_hosts_active'] = "{:,d}".format(fed_hosts_active)
    # output['fed_hosts_active_pct'] = round((float(fed_hosts_active) / total_hosts_active)*100,1)
    # output['sltt_hosts_active'] = "{:,d}".format(sltt_hosts_active)
    # output['sltt_hosts_active_pct'] = round((float(sltt_hosts_active) / total_hosts_active)*100,1)
    # output['private_hosts_active'] = "{:,d}".format(private_hosts_active)
    # output['private_hosts_active_pct'] = round((float(private_hosts_active) / total_hosts_active)*100,1)
    # output['description3'] = ("""---
    # +Data Source: hosts collection
    # +Methodology: Count the addresses where 'state.up' is true with last_change in specified time period, excluding owners that were added after the end of the time period (in ORGS_SCANNED_DURING_FY list).
    # +Notes:
    # +* This is the count of 'active hosts' (with at least one port open), at the time the report is generated.
    # +---""")

    total_vuln_hosts = db.tickets.find({'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}}).distinct('ip_int')
    fed_vuln_hosts = db.tickets.find({'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE[AGENCY_TYPE.FEDERAL]} }).distinct('ip_int')
    sltt_vuln_hosts = db.tickets.find({'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE['SLTT']} }).distinct('ip_int')
    private_vuln_hosts = db.tickets.find({'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE[AGENCY_TYPE.PRIVATE]} }).distinct('ip_int')

    if total_vuln_hosts > 0:
        output['fed_vuln_hosts_pct'] = round((float(len(fed_vuln_hosts)) / len(total_vuln_hosts))*100,1)
        output['sltt_vuln_hosts_pct'] = round((float(len(sltt_vuln_hosts)) / len(total_vuln_hosts))*100,1)
        output['private_vuln_hosts_pct'] = round((float(len(private_vuln_hosts)) / len(total_vuln_hosts))*100,1)
    output['total_vuln_hosts'] = "{:,d}".format(len(total_vuln_hosts))
    output['fed_vuln_hosts'] = "{:,d}".format(len(fed_vuln_hosts))
    output['sltt_vuln_hosts'] = "{:,d}".format(len(sltt_vuln_hosts))
    output['private_vuln_hosts'] = "{:,d}".format(len(private_vuln_hosts))
    output['description4'] = ("""---
Data Source: tickets collection
Methodology: Count the distinct IPs in non-false-positive vulnerability tickets opened during the specified time period.
Notes: None
---""")

    return output

def print_num_addresses_hosts_scanned(FY_START, FY_END, obj):
    print "\nTotal addresses scanned: {:}".format(obj['total_addr'])
    print "* FEDERAL addresses: {:} ({:}%)".format(obj['fed_addr'], obj['fed_addr_pct'])
    print "* SLTT addresses: {:} ({:}%)".format(obj['sltt_addr'], obj['sltt_addr_pct'])
    print "* PRIVATE addresses: {:} ({:}%)".format(obj['private_addr'], obj['private_addr_pct'])
    print obj['description1']

    print "\nTotal hosts scanned: {:}".format(obj['total_hosts_scanned'])
    print "* FEDERAL hosts: {:} ({:}%)".format(obj['fed_hosts_scanned'], obj['fed_hosts_scanned_pct'])
    print "* SLTT hosts: {:} ({:}%)".format(obj['sltt_hosts_scanned'], obj['sltt_hosts_scanned_pct'])
    print "* PRIVATE hosts: {:} ({:}%)".format(obj['private_hosts_scanned'], obj['private_hosts_scanned_pct'])
    print obj['description2']

    #print "\nTotal active hosts currently detected: {:}".format(obj['total_hosts_active'])
    #print "* FEDERAL hosts: {:} ({:}%)".format(obj['fed_hosts_active'], obj['fed_hosts_active_pct'])
    #print "* SLTT hosts: {:} ({:}%)".format(obj['sltt_hosts_active'], obj['sltt_hosts_active_pct'])
    #print "* PRIVATE hosts: {:} ({:}%)".format(obj['private_hosts_active'], obj['private_hosts_active_pct'])
    #print obj['description3']

    print "\nTotal vulnerable hosts detected during scans: {:}".format(obj['total_vuln_hosts'])
    print "* FEDERAL vulnerable hosts: {:} ({:}%)".format(obj['fed_vuln_hosts'], obj['fed_vuln_hosts_pct'])
    print "* SLTT vulnerable hosts: {:} ({:}%)".format(obj['sltt_vuln_hosts'], obj['sltt_vuln_hosts_pct'])
    print "* PRIVATE vulnerable hosts: {:} ({:}%)".format(obj['private_vuln_hosts'], obj['private_vuln_hosts_pct'])
    print obj['description4']

def num_reports_generated(FY_START, FY_END, db):
    total_reports = db.reports.find({'generated_time':{'$gte':FY_START, '$lt':FY_END}, 'report_types':REPORT_TYPE.CYHY})
    fed_reports = db.reports.find({'generated_time':{'$gte':FY_START, '$lt':FY_END}, 'report_types':REPORT_TYPE.CYHY, 'owner': {'$in': ALL_ORGS_BY_TYPE[AGENCY_TYPE.FEDERAL]}})
    sltt_reports = db.reports.find({'generated_time':{'$gte':FY_START, '$lt':FY_END}, 'report_types':REPORT_TYPE.CYHY, 'owner': {'$in': ALL_ORGS_BY_TYPE['SLTT']}})
    private_reports = db.reports.find({'generated_time':{'$gte':FY_START, '$lt':FY_END}, 'report_types':REPORT_TYPE.CYHY, 'owner': {'$in': ALL_ORGS_BY_TYPE[AGENCY_TYPE.PRIVATE]}})

    output = {'total_reports':"{:,d}".format(total_reports.count())}
    output['fed_reports'] = "{:,d}".format(fed_reports.count())
    output['fed_reports_pct'] = round((float(fed_reports.count()) / total_reports.count())*100, 1)
    output['sltt_reports'] = "{:,d}".format(sltt_reports.count())
    output['sltt_reports_pct'] = round((float(sltt_reports.count()) / total_reports.count())*100, 1)
    output['private_reports'] = "{:,d}".format(private_reports.count())
    output['private_reports_pct'] = round((float(private_reports.count()) / total_reports.count())*100, 1)
    output['description'] = ("""---
Data Source: reports collection
Methodology: Count the number of CyHy reports with generated_time in specified time period.
Notes:
* Only Cyber Hygiene reports are included in these counts (report_types == 'CYHY').
---""")

    return output

def print_num_reports_generated(FY_START, FY_END, obj):
    print "\nTotal CyHy reports generated: {:}".format(obj['total_reports'])
    print "* FEDERAL CyHy reports: {:} ({:}%)".format(obj['fed_reports'], obj['fed_reports_pct'])
    print "* SLTT CyHy reports: {:} ({:}%)".format(obj['sltt_reports'], obj['sltt_reports_pct'])
    print "* PRIVATE CyHy reports: {:} ({:}%)".format(obj['private_reports'], obj['private_reports_pct'])
    print obj['description']

def avg_cvss_score(FY_START, FY_END, db):
    pipeline = [ {'$match': {'time': {'$gte':FY_START, '$lt':FY_END} } },
                 {'$group': {'_id':{'ip_int':'$ip_int', 'snapshots':'$snapshots',},
                            'cvss_max':{'$max':'$cvss_base_score'}, } }, # host cvss is the max of any cvss for that host
                 {'$group': {'_id':{},
                            'cvss_avg':{'$avg':'$cvss_max'}, } }, ] # get avg of all host maximums
    overall_cvss = db.vuln_scans.aggregate(pipeline, cursor={})

    pipeline = [ {'$match': {'time': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE[AGENCY_TYPE.FEDERAL]} } },
                 {'$group': {'_id':{'ip_int':'$ip_int', 'snapshots':'$snapshots',},
                            'cvss_max':{'$max':'$cvss_base_score'}, } }, # host cvss is the max of any cvss for that host
                 {'$group': {'_id':{},
                            'cvss_avg':{'$avg':'$cvss_max'}, } }, ] # get avg of all host maximums
    fed_cvss = db.vuln_scans.aggregate(pipeline, cursor={})

    pipeline = [ {'$match': {'time': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE['SLTT']} } },
                 {'$group': {'_id':{'ip_int':'$ip_int', 'snapshots':'$snapshots',},
                            'cvss_max':{'$max':'$cvss_base_score'}, } }, # host cvss is the max of any cvss for that host
                 {'$group': {'_id':{},
                            'cvss_avg':{'$avg':'$cvss_max'}, } }, ] # get avg of all host maximums
    sltt_cvss = db.vuln_scans.aggregate(pipeline, cursor={})

    pipeline = [ {'$match': {'time': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE[AGENCY_TYPE.PRIVATE]} } },
                 {'$group': {'_id':{'ip_int':'$ip_int', 'snapshots':'$snapshots',},
                            'cvss_max':{'$max':'$cvss_base_score'}, } }, # host cvss is the max of any cvss for that host
                 {'$group': {'_id':{},
                            'cvss_avg':{'$avg':'$cvss_max'}, } }, ] # get avg of all host maximums
    private_cvss = db.vuln_scans.aggregate(pipeline, cursor={})

    output = {}
    if len(overall_cvss.get('result')) > 0:
        output['overall_cvss'] = overall_cvss.get('result')[0].get('cvss_avg')
    if len(fed_cvss.get('result')) > 0:
        output['fed_cvss'] = fed_cvss.get('result')[0].get('cvss_avg')
    if len(sltt_cvss.get('result')) > 0:
        output['sltt_cvss'] = sltt_cvss.get('result')[0].get('cvss_avg')
    if len(private_cvss.get('result')) > 0:
        output['private_cvss'] = private_cvss.get('result')[0].get('cvss_avg')
    output['description'] = ("""---
Data Source: vuln_scans collection
Methodology: Output the average of the max cvss_base_score for each IP in all snapshots within the specified time period.
Notes:
* None
---""")

    return output

def print_avg_cvss_score(FY_START, FY_END, obj):
    print "\nAverage CVSS score for hosts with vulnerabilities: {:.3}".format(obj['overall_cvss'])
    print "* FEDERAL average CVSS score: {:.3}".format(obj['fed_cvss'])
    print "* SLTT average CVSS score: {:.3}".format(obj['sltt_cvss'])
    print "* PRIVATE average CVSS score: {:.3}".format(obj['private_cvss'])
    print obj['description']

def unique_vulns(FY_START, FY_END, db):
    pipeline = [ {'$match': {'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END} } },
                 {'$group': {'_id': {'source_id':'$source_id', 'severity':'$details.severity'} } },
                 {'$group': {'_id': { },
                            'low':{'$sum':{'$cond':[{'$eq':['$_id.severity',1]}, 1, 0]}},
                            'medium':{'$sum':{'$cond':[{'$eq':['$_id.severity',2]}, 1, 0]}},
                            'high':{'$sum':{'$cond':[{'$eq':['$_id.severity',3]}, 1, 0]}},
                            'critical':{'$sum':{'$cond':[{'$eq':['$_id.severity',4]}, 1, 0]}},
                            'total':{'$sum':1},
                            } }, ]
    overall_uniq_vulns = db.tickets.aggregate(pipeline, cursor={})

    pipeline = [ {'$match': {'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE[AGENCY_TYPE.FEDERAL]} } },
                 {'$group': {'_id': {'source_id':'$source_id', 'severity':'$details.severity'} } },
                 {'$group': {'_id': { },
                            'low':{'$sum':{'$cond':[{'$eq':['$_id.severity',1]}, 1, 0]}},
                            'medium':{'$sum':{'$cond':[{'$eq':['$_id.severity',2]}, 1, 0]}},
                            'high':{'$sum':{'$cond':[{'$eq':['$_id.severity',3]}, 1, 0]}},
                            'critical':{'$sum':{'$cond':[{'$eq':['$_id.severity',4]}, 1, 0]}},
                            'total':{'$sum':1},
                            } }, ]
    fed_uniq_vulns = db.tickets.aggregate(pipeline, cursor={})

    pipeline = [ {'$match': {'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE['SLTT']} } },
                 {'$group': {'_id': {'source_id':'$source_id', 'severity':'$details.severity'} } },
                 {'$group': {'_id': { },
                            'low':{'$sum':{'$cond':[{'$eq':['$_id.severity',1]}, 1, 0]}},
                            'medium':{'$sum':{'$cond':[{'$eq':['$_id.severity',2]}, 1, 0]}},
                            'high':{'$sum':{'$cond':[{'$eq':['$_id.severity',3]}, 1, 0]}},
                            'critical':{'$sum':{'$cond':[{'$eq':['$_id.severity',4]}, 1, 0]}},
                            'total':{'$sum':1},
                            } }, ]
    sltt_uniq_vulns = db.tickets.aggregate(pipeline, cursor={})

    pipeline = [ {'$match': {'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE[AGENCY_TYPE.PRIVATE]} } },
                 {'$group': {'_id': {'source_id':'$source_id', 'severity':'$details.severity'} } },
                 {'$group': {'_id': { },
                            'low':{'$sum':{'$cond':[{'$eq':['$_id.severity',1]}, 1, 0]}},
                            'medium':{'$sum':{'$cond':[{'$eq':['$_id.severity',2]}, 1, 0]}},
                            'high':{'$sum':{'$cond':[{'$eq':['$_id.severity',3]}, 1, 0]}},
                            'critical':{'$sum':{'$cond':[{'$eq':['$_id.severity',4]}, 1, 0]}},
                            'total':{'$sum':1},
                            } }, ]
    private_uniq_vulns = db.tickets.aggregate(pipeline, cursor={})

    '''
    pipeline = [ {'$match': {'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$nin': FEDERAL+SLTT+PRIVATE} } },
                 {'$group': {'_id': {'source_id':'$source_id', 'severity':'$details.severity'} } },
                 {'$group': {'_id': { },
                            'low':{'$sum':{'$cond':[{'$eq':['$_id.severity',1]}, 1, 0]}},
                            'medium':{'$sum':{'$cond':[{'$eq':['$_id.severity',2]}, 1, 0]}},
                            'high':{'$sum':{'$cond':[{'$eq':['$_id.severity',3]}, 1, 0]}},
                            'critical':{'$sum':{'$cond':[{'$eq':['$_id.severity',4]}, 1, 0]}},
                            'total':{'$sum':1},
                            } }, ]
    other_uniq_vulns = db.tickets.aggregate(pipeline, cursor={})
    '''

    if len(overall_uniq_vulns.get('result')) > 0:
        overall_total = overall_uniq_vulns.get('result')[0].get('total')
        overall_critical = overall_uniq_vulns.get('result')[0].get('critical')
        overall_high = overall_uniq_vulns.get('result')[0].get('high')
        overall_med = overall_uniq_vulns.get('result')[0].get('medium')
        overall_low = overall_uniq_vulns.get('result')[0].get('low')
    else:
        overall_total = 0
        overall_critical = 0
        overall_high = 0
        overall_med = 0
        overall_low = 0

    if len(fed_uniq_vulns.get('result')) > 0:
        fed_total = fed_uniq_vulns.get('result')[0].get('total')
        fed_critical = fed_uniq_vulns.get('result')[0].get('critical')
        fed_high = fed_uniq_vulns.get('result')[0].get('high')
        fed_med = fed_uniq_vulns.get('result')[0].get('medium')
        fed_low = fed_uniq_vulns.get('result')[0].get('low')
    else:
        fed_total = 0
        fed_critical = 0
        fed_high = 0
        fed_med = 0
        fed_low = 0

    if len(sltt_uniq_vulns.get('result')) > 0:
        sltt_total = sltt_uniq_vulns.get('result')[0].get('total')
        sltt_critical = sltt_uniq_vulns.get('result')[0].get('critical')
        sltt_high = sltt_uniq_vulns.get('result')[0].get('high')
        sltt_med = sltt_uniq_vulns.get('result')[0].get('medium')
        sltt_low = sltt_uniq_vulns.get('result')[0].get('low')
    else:
        sltt_total = 0
        sltt_critical = 0
        sltt_high = 0
        sltt_med = 0
        sltt_low = 0

    if len(private_uniq_vulns.get('result')) > 0:
        private_total = private_uniq_vulns.get('result')[0].get('total')
        private_critical = private_uniq_vulns.get('result')[0].get('critical')
        private_high = private_uniq_vulns.get('result')[0].get('high')
        private_med = private_uniq_vulns.get('result')[0].get('medium')
        private_low = private_uniq_vulns.get('result')[0].get('low')
    else:
        private_total = 0
        private_critical = 0
        private_high = 0
        private_med = 0
        private_low = 0

    mylist = []

    if overall_total > 0:
        myarg = {'type': 'Total',
                  'total': "{:,d}".format(overall_total),
                  'crit': "{:,d}".format(overall_critical),
                  'crit_pct': round((float(overall_critical) / overall_total)*100,1),
                  'high': "{:,d}".format(overall_high),
                  'high_pct': round((float(overall_high) / overall_total)*100,1),
                  'med': "{:,d}".format(overall_med),
                  'med_pct': round((float(overall_med) / overall_total)*100,1),
                  'low': "{:,d}".format(overall_low),
                  'low_pct': round((float(overall_low) / overall_total)*100,1)
                  }
    else:
        myarg = {'type': 'Total',
                  'total': "{:,d}".format(overall_total),
                  'crit': "{:,d}".format(overall_critical),
                  'crit_pct': 'NaN',
                  'high': "{:,d}".format(overall_high),
                  'high_pct': 'NaN',
                  'med': "{:,d}".format(overall_med),
                  'med_pct': 'NaN',
                  'low': "{:,d}".format(overall_low),
                  'low_pct': 'NaN'
                  }
    mylist.append(myarg)

    if fed_total > 0:
        myarg = {'type': 'FEDERAL',
                  'total': "{:,d}".format(fed_total),
                  'crit': "{:,d}".format(fed_critical),
                  'crit_pct': round((float(fed_critical) / fed_total)*100,1),
                  'high': "{:,d}".format(fed_high),
                  'high_pct': round((float(fed_high) / fed_total)*100,1),
                  'med': "{:,d}".format(fed_med),
                  'med_pct': round((float(fed_med) / fed_total)*100,1),
                  'low': "{:,d}".format(fed_low),
                  'low_pct': round((float(fed_low) / fed_total)*100,1)
                  }
    else:
        myarg = {'type': 'FEDERAL',
                  'total': "{:,d}".format(fed_total),
                  'crit': "{:,d}".format(fed_critical),
                  'crit_pct': 'NaN',
                  'high': "{:,d}".format(fed_high),
                  'high_pct': 'NaN',
                  'med': "{:,d}".format(fed_med),
                  'med_pct': 'NaN',
                  'low': "{:,d}".format(fed_low),
                  'low_pct': 'NaN'
                  }
    mylist.append(myarg)

    if sltt_total > 0:
        myarg = {'type': 'SLTT',
                  'total': "{:,d}".format(sltt_total),
                  'crit': "{:,d}".format(sltt_critical),
                  'crit_pct': round((float(sltt_critical) / sltt_total)*100,1),
                  'high': "{:,d}".format(sltt_high),
                  'high_pct': round((float(sltt_high) / sltt_total)*100,1),
                  'med': "{:,d}".format(sltt_med),
                  'med_pct': round((float(sltt_med) / sltt_total)*100,1),
                  'low': "{:,d}".format(sltt_low),
                  'low_pct': round((float(sltt_low) / sltt_total)*100,1)
                  }
    else:
        myarg = {'type': 'SLTT',
                  'total': "{:,d}".format(sltt_total),
                  'crit': "{:,d}".format(sltt_critical),
                  'crit_pct': 'NaN',
                  'high': "{:,d}".format(sltt_high),
                  'high_pct': 'NaN',
                  'med': "{:,d}".format(sltt_med),
                  'med_pct': 'NaN',
                  'low': "{:,d}".format(sltt_low),
                  'low_pct': 'NaN'
                  }
    mylist.append(myarg)

    if private_total > 0:
        myarg = {'type': 'PRIVATE',
                  'total': "{:,d}".format(private_total),
                  'crit': "{:,d}".format(private_critical),
                  'crit_pct': round((float(private_critical) / private_total)*100,1),
                  'high': "{:,d}".format(private_high),
                  'high_pct': round((float(private_high) / private_total)*100,1),
                  'med': "{:,d}".format(private_med),
                  'med_pct': round((float(private_med) / private_total)*100,1),
                  'low': "{:,d}".format(private_low),
                  'low_pct': round((float(private_low) / private_total)*100,1)
                  }
    else:
        myarg = {'type': 'PRIVATE',
                  'total': "{:,d}".format(private_total),
                  'crit': "{:,d}".format(private_critical),
                  'crit_pct': 'NaN',
                  'high': "{:,d}".format(private_high),
                  'high_pct': 'NaN',
                  'med': "{:,d}".format(private_med),
                  'med_pct': 'NaN',
                  'low': "{:,d}".format(private_low),
                  'low_pct': 'NaN'
                  }
    mylist.append(myarg)

    output = {'data':mylist}
    output['description'] = ("""---
Data Source: tickets collection
Methodology: Group vulnerability tickets in the specified time period by source_id (unique id for the vuln) and by severity. False positive tickets not included.
Notes:
* Since the name of a vuln can change over time, we use the source_id for our grouping.
---""")

    return output

def print_unique_vulns(FY_START, FY_END, obj):
    for item in obj['data']:
        print "\n{:} unique vulnerabilities discovered: {:}".format(item['type'], item['total'])
        print "  * Critical: {:} ({:}%)".format(item['crit'], item['crit_pct'])
        print "  * High: {:} ({:}%)".format(item['high'], item['high_pct'])
        print "  * Medium: {:} ({:}%)".format(item['med'], item['med_pct'])
        print "  * Low: {:} ({:}%)".format(item['low'], item['low_pct'])

    print obj['description']

def new_vuln_detections(FY_START, FY_END, db):
    pipeline = [ {'$match': {'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END} } },
                 {'$group': {'_id': { },
                             'low':{'$sum':{'$cond':[{'$eq':['$details.severity',1]}, 1, 0]}},
                             'medium':{'$sum':{'$cond':[{'$eq':['$details.severity',2]}, 1, 0]}},
                             'high':{'$sum':{'$cond':[{'$eq':['$details.severity',3]}, 1, 0]}},
                             'critical':{'$sum':{'$cond':[{'$eq':['$details.severity',4]}, 1, 0]}},
                             'total':{'$sum':1},
                             } }, ]
    overall_vulns = db.tickets.aggregate(pipeline, cursor={})

    pipeline = [ {'$match': {'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE[AGENCY_TYPE.FEDERAL]} } },
                 {'$group': {'_id': { },
                             'low':{'$sum':{'$cond':[{'$eq':['$details.severity',1]}, 1, 0]}},
                             'medium':{'$sum':{'$cond':[{'$eq':['$details.severity',2]}, 1, 0]}},
                             'high':{'$sum':{'$cond':[{'$eq':['$details.severity',3]}, 1, 0]}},
                             'critical':{'$sum':{'$cond':[{'$eq':['$details.severity',4]}, 1, 0]}},
                             'total':{'$sum':1},
                             } }, ]
    fed_vulns = db.tickets.aggregate(pipeline, cursor={})

    pipeline = [ {'$match': {'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE['SLTT']} } },
                 {'$group': {'_id': { },
                             'low':{'$sum':{'$cond':[{'$eq':['$details.severity',1]}, 1, 0]}},
                             'medium':{'$sum':{'$cond':[{'$eq':['$details.severity',2]}, 1, 0]}},
                             'high':{'$sum':{'$cond':[{'$eq':['$details.severity',3]}, 1, 0]}},
                             'critical':{'$sum':{'$cond':[{'$eq':['$details.severity',4]}, 1, 0]}},
                             'total':{'$sum':1},
                             } }, ]
    sltt_vulns = db.tickets.aggregate(pipeline, cursor={})

    pipeline = [ {'$match': {'false_positive':False, 'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$in': ALL_ORGS_BY_TYPE[AGENCY_TYPE.PRIVATE]} } },
                 {'$group': {'_id': { },
                             'low':{'$sum':{'$cond':[{'$eq':['$details.severity',1]}, 1, 0]}},
                             'medium':{'$sum':{'$cond':[{'$eq':['$details.severity',2]}, 1, 0]}},
                             'high':{'$sum':{'$cond':[{'$eq':['$details.severity',3]}, 1, 0]}},
                             'critical':{'$sum':{'$cond':[{'$eq':['$details.severity',4]}, 1, 0]}},
                             'total':{'$sum':1},
                             } }, ]
    private_vulns = db.tickets.aggregate(pipeline, cursor={})

    '''
    pipeline = [ {'$match': {'time_opened': {'$gte':FY_START, '$lt':FY_END}, 'owner': {'$nin': FEDERAL+SLTT+PRIVATE} } },
                 {'$group': {'_id': { },
                             'low':{'$sum':{'$cond':[{'$eq':['$details.severity',1]}, 1, 0]}},
                             'medium':{'$sum':{'$cond':[{'$eq':['$details.severity',2]}, 1, 0]}},
                             'high':{'$sum':{'$cond':[{'$eq':['$details.severity',3]}, 1, 0]}},
                             'critical':{'$sum':{'$cond':[{'$eq':['$details.severity',4]}, 1, 0]}},
                             'total':{'$sum':1},
                             } }, ]
    other_vulns = db.tickets.aggregate(pipeline, cursor={})
    '''

    if len(overall_vulns.get('result')) > 0:
        overall_total = overall_vulns.get('result')[0].get('total')
        overall_critical = overall_vulns.get('result')[0].get('critical')
        overall_high = overall_vulns.get('result')[0].get('high')
        overall_med = overall_vulns.get('result')[0].get('medium')
        overall_low = overall_vulns.get('result')[0].get('low')
    else:
        overall_total = 0
        overall_critical = 0
        overall_high = 0
        overall_med = 0
        overall_low = 0

    if len(fed_vulns.get('result')) > 0:
        fed_total = fed_vulns.get('result')[0].get('total')
        fed_critical = fed_vulns.get('result')[0].get('critical')
        fed_high = fed_vulns.get('result')[0].get('high')
        fed_med = fed_vulns.get('result')[0].get('medium')
        fed_low = fed_vulns.get('result')[0].get('low')
    else:
        fed_total = 0
        fed_critical = 0
        fed_high = 0
        fed_med = 0
        fed_low = 0

    if len(sltt_vulns.get('result')) > 0:
        sltt_total = sltt_vulns.get('result')[0].get('total')
        sltt_critical = sltt_vulns.get('result')[0].get('critical')
        sltt_high = sltt_vulns.get('result')[0].get('high')
        sltt_med = sltt_vulns.get('result')[0].get('medium')
        sltt_low = sltt_vulns.get('result')[0].get('low')
    else:
        sltt_total = 0
        sltt_critical = 0
        sltt_high = 0
        sltt_med = 0
        sltt_low = 0

    if len(private_vulns.get('result')) > 0:
        private_total = private_vulns.get('result')[0].get('total')
        private_critical = private_vulns.get('result')[0].get('critical')
        private_high = private_vulns.get('result')[0].get('high')
        private_med = private_vulns.get('result')[0].get('medium')
        private_low = private_vulns.get('result')[0].get('low')
    else:
        private_total = 0
        private_critical = 0
        private_high = 0
        private_med = 0
        private_low = 0

    mylist = []

    if overall_total > 0:
        myarg = {'type': 'Total',
                  'total': "{:,d}".format(overall_total),
                  'crit': "{:,d}".format(overall_critical),
                  'crit_pct': round((float(overall_critical) / overall_total)*100,1),
                  'high': "{:,d}".format(overall_high),
                  'high_pct': round((float(overall_high) / overall_total)*100,1),
                  'med': "{:,d}".format(overall_med),
                  'med_pct': round((float(overall_med) / overall_total)*100,1),
                  'low': "{:,d}".format(overall_low),
                  'low_pct': round((float(overall_low) / overall_total)*100,1)
                  }
    else:
        myarg = {'type': 'Total',
                  'total': "{:,d}".format(overall_total),
                  'crit': "{:,d}".format(overall_critical),
                  'crit_pct': 'NaN',
                  'high': "{:,d}".format(overall_high),
                  'high_pct': 'NaN',
                  'med': "{:,d}".format(overall_med),
                  'med_pct': 'NaN',
                  'low': "{:,d}".format(overall_low),
                  'low_pct': 'NaN'
                  }
    mylist.append(myarg)

    if fed_total > 0:
        myarg = {'type': 'FEDERAL',
                  'total': "{:,d}".format(fed_total),
                  'crit': "{:,d}".format(fed_critical),
                  'crit_pct': round((float(fed_critical) / fed_total)*100,1),
                  'high': "{:,d}".format(fed_high),
                  'high_pct': round((float(fed_high) / fed_total)*100,1),
                  'med': "{:,d}".format(fed_med),
                  'med_pct': round((float(fed_med) / fed_total)*100,1),
                  'low': "{:,d}".format(fed_low),
                  'low_pct': round((float(fed_low) / fed_total)*100,1)
                  }
    else:
        myarg = {'type': 'FEDERAL',
                  'total': "{:,d}".format(fed_total),
                  'crit': "{:,d}".format(fed_critical),
                  'crit_pct': 'NaN',
                  'high': "{:,d}".format(fed_high),
                  'high_pct': 'NaN',
                  'med': "{:,d}".format(fed_med),
                  'med_pct': 'NaN',
                  'low': "{:,d}".format(fed_low),
                  'low_pct': 'NaN'
                  }
    mylist.append(myarg)

    if sltt_total > 0:
        myarg = {'type': 'SLTT',
                  'total': "{:,d}".format(sltt_total),
                  'crit': "{:,d}".format(sltt_critical),
                  'crit_pct': round((float(sltt_critical) / sltt_total)*100,1),
                  'high': "{:,d}".format(sltt_high),
                  'high_pct': round((float(sltt_high) / sltt_total)*100,1),
                  'med': "{:,d}".format(sltt_med),
                  'med_pct': round((float(sltt_med) / sltt_total)*100,1),
                  'low': "{:,d}".format(sltt_low),
                  'low_pct': round((float(sltt_low) / sltt_total)*100,1)
                  }
    else:
        myarg = {'type': 'SLTT',
                  'total': "{:,d}".format(sltt_total),
                  'crit': "{:,d}".format(sltt_critical),
                  'crit_pct': 'NaN',
                  'high': "{:,d}".format(sltt_high),
                  'high_pct': 'NaN',
                  'med': "{:,d}".format(sltt_med),
                  'med_pct': 'NaN',
                  'low': "{:,d}".format(sltt_low),
                  'low_pct': 'NaN'
                  }
    mylist.append(myarg)

    if private_total > 0:
        myarg = {'type': 'PRIVATE',
                  'total': "{:,d}".format(private_total),
                  'crit': "{:,d}".format(private_critical),
                  'crit_pct': round((float(private_critical) / private_total)*100,1),
                  'high': "{:,d}".format(private_high),
                  'high_pct': round((float(private_high) / private_total)*100,1),
                  'med': "{:,d}".format(private_med),
                  'med_pct': round((float(private_med) / private_total)*100,1),
                  'low': "{:,d}".format(private_low),
                  'low_pct': round((float(private_low) / private_total)*100,1)
                  }
    else:
        myarg = {'type': 'PRIVATE',
                  'total': "{:,d}".format(private_total),
                  'crit': "{:,d}".format(private_critical),
                  'crit_pct': 'NaN',
                  'high': "{:,d}".format(private_high),
                  'high_pct': 'NaN',
                  'med': "{:,d}".format(private_med),
                  'med_pct': 'NaN',
                  'low': "{:,d}".format(private_low),
                  'low_pct': 'NaN'
                  }
    mylist.append(myarg)

    output = {'data':mylist}
    output['description'] = ("""---
Data Source: tickets collection
Methodology: Group all vulnerability tickets in the specified time period by severity. False positive tickets not included.
Notes: None
---""")

    return output

def print_new_vuln_detections(FY_START, FY_END, obj):
    for item in obj['data']:
        print "\n{:} vulnerability tickets opened: {:}".format(item['type'], item['total'])
        print "  * Critical: {:} ({:}%)".format(item['crit'], item['crit_pct'])
        print "  * High: {:} ({:}%)".format(item['high'], item['high_pct'])
        print "  * Medium: {:} ({:}%)".format(item['med'], item['med_pct'])
        print "  * Low: {:} ({:}%)".format(item['low'], item['low_pct'])

    print obj['description']

def categorize_orgs(db):
    global ALL_ORGS_BY_TYPE, ALL_STAKEHOLDERS_BY_TYPE

    ALL_ORGS_BY_TYPE = db.RequestDoc.get_owner_types(as_lists=True, stakeholders_only=False)
    ALL_ORGS_BY_TYPE['SLTT'] = ALL_ORGS_BY_TYPE[AGENCY_TYPE.STATE] + ALL_ORGS_BY_TYPE[AGENCY_TYPE.LOCAL] + ALL_ORGS_BY_TYPE[AGENCY_TYPE.TRIBAL] + ALL_ORGS_BY_TYPE[AGENCY_TYPE.TERRITORIAL]

    ALL_STAKEHOLDERS_BY_TYPE = db.RequestDoc.get_owner_types(as_lists=True, stakeholders_only=True)
    ALL_STAKEHOLDERS_BY_TYPE['ALL'] = list()
    for key,value in ALL_STAKEHOLDERS_BY_TYPE.items():
        ALL_STAKEHOLDERS_BY_TYPE['ALL'] += value
    ALL_STAKEHOLDERS_BY_TYPE['SLTT'] = ALL_STAKEHOLDERS_BY_TYPE[AGENCY_TYPE.STATE] + ALL_STAKEHOLDERS_BY_TYPE[AGENCY_TYPE.LOCAL] + ALL_STAKEHOLDERS_BY_TYPE[AGENCY_TYPE.TRIBAL] + ALL_STAKEHOLDERS_BY_TYPE[AGENCY_TYPE.TERRITORIAL]

def main(argv=None):
    args = docopt(__doc__, version='v0.0.1')
    db = database.db_from_config(args['--section'])
    categorize_orgs(db)

    if args['STARTDATE'] != None and args['ENDDATE'] != None:
        try:
            t = time.strptime(args['STARTDATE'], "%Y-%m-%d")
            FY_START = datetime.datetime(*t[:4])
            t = time.strptime(args['ENDDATE'], "%Y-%m-%d")
            FY_END = datetime.datetime(*t[:4])
        except (ValueError, TypeError), e:
            sys.exit('Error: Please enter dates as YYYY-MM-DD')
    else:
        sys.exit('See help option [-h] for usage')

    print ("\nFiscal Year Summary (%s - %s)" % (FY_START, FY_END))
    print_vuln_ticket_counts(FY_START, FY_END, vuln_ticket_counts(FY_START, FY_END, db))
    # print_top_vulns(FY_START, FY_END, top_vulns(FY_START, FY_END, db))
    # print_top_OS(FY_START, FY_END, top_OS(FY_START, FY_END, db))
    # print_top_vuln_services(FY_START, FY_END, top_vuln_services(FY_START, FY_END, db))
    # print_top_services(FY_START, FY_END, top_services(FY_START, FY_END, db))
    # print_num_orgs_scanned(FY_START, FY_END, num_orgs_scanned(FY_START, FY_END, db))
    # print_num_addresses_hosts_scanned(FY_START, FY_END, num_addresses_hosts_scanned(FY_START, FY_END, db))
    # print_num_reports_generated(FY_START, FY_END, num_reports_generated(FY_START, FY_END, db))
    # print_avg_cvss_score(FY_START, FY_END, avg_cvss_score(FY_START, FY_END, db))
    # print_unique_vulns(FY_START, FY_END, unique_vulns(FY_START, FY_END, db))
    # print_new_vuln_detections(FY_START, FY_END, new_vuln_detections(FY_START, FY_END, db))

    # import IPython; IPython.embed() #<<< BREAKPOINT >>>
    # sys.exit(0)

if __name__=='__main__':
    main(sys.argv[1:])
