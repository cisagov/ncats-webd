#!/usr/bin/env python
'''Generate list of CyHy customers by risk rating.

Usage:
  COMMAND_NAME [--section SECTION]
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.

'''
from cyhy.db import database
from cyhy.util import util
from cyhy.core import SCAN_TYPE
from docopt import docopt
import re
import numpy as np
import datetime
import sys

def severity_calculation(db, severity):
    '''Step 1: Average # Critical
    For each stakeholder, get the average number of critical vulnerabilities (vulnerabilities.critical) from each snapshot from Start-Date to End-Date'''
    # stakeholder:True for just the top level orgs or scan_type:CYHY for children as well
    customer_list = [s['_id'] for s in db.RequestDoc.collection.find({'scan_types':SCAN_TYPE.CYHY}, {'_id':1})]
    sev_customer_bundle = list()
    open_customer_bundle = list()
    close_customer_bundle = list()

    pipeline = [
        {'$match':{'owner':{'$in':customer_list},'tix_msec_open':{'$exists':True}}},
        {'$project':{'owner':1,'tix_msec_open':1,'tix_msec_to_close':1,'vulnerabilities':1}},
        {'$group':{'_id':'$owner','snapshots':{'$push':'$$ROOT'}}}
    ]
    master_snaps = db.snapshots.aggregate(pipeline, allowDiskUse=True, cursor={})
    #import IPython; IPython.embed() #<<< BREAKPOINT >>>
    #sys.exit(0)

    for i in master_snaps:
        owner = i['_id']

        sev_total = 0
        open_total = 0
        close_total = 0
        for snap in i['snapshots']:
            sev_total += snap['vulnerabilities'][severity]
            if snap['tix_msec_open'][severity]['median'] != None:
                open_total += snap['tix_msec_open'][severity]['median']
            if snap['tix_msec_to_close'][severity]['median'] != None:
                close_total += snap['tix_msec_to_close'][severity]['median']

        if len(i['snapshots']) > 0:
            sev_avg = sev_total / len(i['snapshots'])
            sev_customer_bundle.append([owner, sev_avg])
            open_avg = open_total / len(i['snapshots'])
            open_customer_bundle.append([owner, open_avg])
            close_avg = close_total / len(i['snapshots'])
            close_customer_bundle.append([owner, close_avg])

    '''Step 2: Critical Weighted
    For each stakeholder, Average # Critical * 10'''
    multiplier = 0.0
    if severity == 'critical':
        multiplier = 10
    elif severity == 'high':
        multiplier = 9.9
    elif severity == 'medium':
        multiplier = 6.9
    else:
        multiplier = 3.9

    for i in sev_customer_bundle:
        i.append(i[1] * multiplier)
    for i in open_customer_bundle:
        i.append(i[1] * multiplier)
    for i in close_customer_bundle:
        i.append(i[1] * multiplier)

    '''Step 3: Critical Rank
    For all stakeholders, rank by Critical Weighted from 1(highest score) to N(lowest score)'''
    sorted_by_second1 = sorted(sev_customer_bundle, key=lambda tup: tup[1], reverse=True)
    sorted_by_second2 = sorted(open_customer_bundle, key=lambda tup: tup[1], reverse=True)
    sorted_by_second3 = sorted(close_customer_bundle, key=lambda tup: tup[1], reverse=True)


    '''Step 4: Critical Relative Score
    For all stakeholders, (1/Critical Rank)*100'''
    counter = 0.0
    for i in sorted_by_second1:
        counter+=1.0
        i.append( (1.0/counter) * 100.0 )
    counter = 0.0
    for i in sorted_by_second2:
        counter+=1.0
        i.append( (1.0/counter) * 100.0 )
    counter = 0.0
    for i in sorted_by_second3:
        counter+=1.0
        i.append( (1.0/counter) * 100.0 )

    return (sorted_by_second1, sorted_by_second2, sorted_by_second3)
    #REPEAT STEPS 1-4 FOR:
    #vulnerabilities.high
    #vulnerabilities.medium
    #vulnerabilities.low

def get_ranking_lists(db):
    critical_list = severity_calculation(db, 'critical')
    avg_relative_critical_list = sorted(critical_list[0], key=lambda tup: tup[0])
    avg_max_vuln_alive_critical_list = sorted(critical_list[1], key=lambda tup: tup[0])
    avg_max_time_mitigate_critical_list = sorted(critical_list[2], key=lambda tup: tup[0])

    high_list =  severity_calculation(db, 'high')
    avg_relative_high_list = sorted(high_list[0], key=lambda tup: tup[0])
    avg_max_vuln_alive_high_list = sorted(high_list[1], key=lambda tup: tup[0])
    avg_max_time_mitigate_high_list = sorted(high_list[2], key=lambda tup: tup[0])

    medium_list = severity_calculation(db, 'medium')
    avg_relative_medium_list = sorted(medium_list[0], key=lambda tup: tup[0])
    avg_max_vuln_alive_medium_list = sorted(medium_list[1], key=lambda tup: tup[0])
    avg_max_time_mitigate_medium_list = sorted(medium_list[2], key=lambda tup: tup[0])

    low_list =  severity_calculation(db, 'low')
    avg_relative_low_list = sorted(low_list[0], key=lambda tup: tup[0])
    avg_max_vuln_alive_low_list = sorted(low_list[1], key=lambda tup: tup[0])
    avg_max_time_mitigate_low_list = sorted(low_list[2], key=lambda tup: tup[0])

    #Step 5: Average # Vulnerability Relative Score
    #For all stakeholders, Critical Relative Score + High Relative Score + Medium Relative Score + Low Relative Score
    avg_relative_score = []
    for a,b,c,d in zip(avg_relative_critical_list,avg_relative_high_list,avg_relative_medium_list,avg_relative_low_list):
        avg_relative_score.append( (a[0], a[3] + b[3] + c[3] + d[3]) )

    #Step 6: Average # Vulnerability Ranking
    #For all stakeholders, rank Average Relative Score from 1(highest score) to N(lowest score)
    average_vulnerability_ranking = []
    sorted_by_second1 = sorted(avg_relative_score, key=lambda tup: tup[1], reverse=True)

    for i in sorted_by_second1:
        average_vulnerability_ranking.append((i[0],db.RequestDoc.find_one({'_id':i[0]})['agency']['name'],round(i[1],2)))

    #REPEAT STEPS 1-6 FOR:

    #Average Max Vulnerability Alive (tix_msec_open.[c/h/m/l].max)
    average_max_vulnerability_alive_ranking = []
    avg_max_vuln_alive_score = []
    for a,b,c,d in zip(avg_max_vuln_alive_critical_list,avg_max_vuln_alive_high_list,avg_max_vuln_alive_medium_list,avg_max_vuln_alive_low_list):
        avg_max_vuln_alive_score.append( (a[0], a[3] + b[3] + c[3] + d[3]) )

    sorted_by_second2 = sorted(avg_max_vuln_alive_score, key=lambda tup: tup[1], reverse=True)
    for i in sorted_by_second2:
        average_max_vulnerability_alive_ranking.append((i[0],db.RequestDoc.find_one({'_id':i[0]})['agency']['name'],round(i[1],2)))

    #Average Max Time to Mitigate (tix_msec_to_close.[c/h/m/l].max)
    average_max_time_to_mitigate = []
    avg_max_time_mitigate_score = []
    for a,b,c,d in zip(avg_max_time_mitigate_critical_list,avg_max_time_mitigate_high_list,avg_max_time_mitigate_medium_list,avg_max_time_mitigate_low_list):
        avg_max_time_mitigate_score.append( (a[0], a[3] + b[3] + c[3] + d[3]) )

    sorted_by_second3 = sorted(avg_max_time_mitigate_score, key=lambda tup: tup[1], reverse=True)
    for i in sorted_by_second3:
        average_max_time_to_mitigate.append((i[0],db.RequestDoc.find_one({'_id':i[0]})['agency']['name'],round(i[1],2)))

    #Step 7: Total Relative Score
    #For all stakeholders, Average # Vulnerability Relative Score + Average Max Vulnerability Age Relative Score + Average Max Time Mitigate Relative Score
    total_relative_score = []
    for a,b,c in zip(avg_relative_score,avg_max_vuln_alive_score,avg_max_time_mitigate_score):
        total_relative_score.append( (a[0], a[1] + b[1] + c[1]) )

    #Step 8: Overall Rank/ "One Score"
    overall_rank = []
    #For all stakeholders, rank Total Relative Score from 1(highest score) to N(lowest score)
    sorted_by_second4 = sorted(total_relative_score, key=lambda tup: tup[1], reverse=True)
    for i in sorted_by_second4:
        overall_rank.append((i[0],db.RequestDoc.find_one({'_id':i[0]})['agency']['name'],round(i[1],2)))

    print average_vulnerability_ranking
    print average_max_vulnerability_alive_ranking
    print average_max_time_to_mitigate
    print overall_rank

    return average_vulnerability_ranking, average_max_vulnerability_alive_ranking, average_max_time_to_mitigate, overall_rank

def main():
    global __doc__
    __doc__ = re.sub('COMMAND_NAME', __file__, __doc__)
    args = docopt(__doc__, version='v0.0.1')
    db = database.db_from_config(args['--section'])
    get_ranking_lists(db)

if __name__ == '__main__':
    main()
