#!/usr/bin/env python
'''
usage: ticket-report.py [-h] [--section config-section]

Report on tickets

optional arguments:
  -h, --help            show this help message and exit
  --section config-section, -s config-section
                        use config file section
'''

import sys
import os
from docopt import docopt
import netaddr
import datetime
from cyhy.db import database
from cyhy.util import util
from cyhy.core.common import AGENCY_TYPE, REPORT_TYPE
from dateutil.relativedelta import relativedelta

def get_owner_types_ci(db,as_lists=False, stakeholders_only=False):
    '''returns a dict of types to owners.  The owners can be in a set or list depending on "as_lists" parameter.
       "stakeholders_only" parameter eliminates non-stakeholders from the dict.'''
    types = dict()
    CI_CHILDREN = db.RequestDoc.find_one({'_id':'CRITICAL_INFRASTRUCTURE'})['children']
    for agency_type in CI_CHILDREN:
        types[agency_type] = set()
        all_agency_type_descendants = db.RequestDoc.get_all_descendants(agency_type)
        if stakeholders_only:
            for org in db.RequestDoc.find({'_id':{'$in':all_agency_type_descendants}}):
                if org['stakeholder']:
                    types[agency_type].add(org['_id'])
        else:
            types[agency_type] = set(all_agency_type_descendants)
    # convert to a dict of lists
    if not as_lists:
        return types
    result = dict()
    for k,v in types.items():
        result[k] = list(v)
    return result

def scanning_breakdown(db):
    all_stakeholders_by_type = db.RequestDoc.get_owner_types(as_lists=True,stakeholders_only=True)
    fed = len(all_stakeholders_by_type['FEDERAL'])
    stakeholders_scanned = {'fed':fed}

    state = len(all_stakeholders_by_type['STATE'])
    local = len(all_stakeholders_by_type['LOCAL'])
    tribal = len(all_stakeholders_by_type['TRIBAL'])
    territorial = len(all_stakeholders_by_type['TERRITORIAL'])

    stakeholders_scanned['sltt'] = state+local+tribal+territorial
    stakeholders_scanned['state'] = state
    stakeholders_scanned['local'] = local
    stakeholders_scanned['tribal'] = tribal
    stakeholders_scanned['territorial'] = territorial

    private = len(all_stakeholders_by_type['PRIVATE'])
    stakeholders_scanned['private'] = private

    ci_stakeholders_by_type = get_owner_types_ci(db,as_lists=True,stakeholders_only=True)

    stakeholders_scanned['chemical'] = len(ci_stakeholders_by_type['CI_CHEMICAL'])
    stakeholders_scanned['commercial_facilities'] = len(ci_stakeholders_by_type['CI_COMMERCIAL_FACILITIES'])
    stakeholders_scanned['communications'] = len(ci_stakeholders_by_type['CI_COMMUNICATIONS'])
    stakeholders_scanned['critical_manufacturing'] = len(ci_stakeholders_by_type['CI_CRITICAL_MANUFACTURING'])
    stakeholders_scanned['dams'] = len(ci_stakeholders_by_type['CI_DAMS'])
    stakeholders_scanned['defense_industrial_base'] = len(ci_stakeholders_by_type['CI_DEFENSE_INDUSTRIAL_BASE'])
    stakeholders_scanned['emergency_services'] = len(ci_stakeholders_by_type['CI_EMERGENCY_SERVICES'])
    stakeholders_scanned['energy'] = len(ci_stakeholders_by_type['CI_ENERGY'])
    stakeholders_scanned['financial_services'] = len(ci_stakeholders_by_type['CI_FINANCIAL_SERVICES'])
    stakeholders_scanned['food_and_agriculture'] = len(ci_stakeholders_by_type['CI_FOOD_AND_AGRICULTURE'])
    stakeholders_scanned['government_facilities'] = len(ci_stakeholders_by_type['CI_GOVERNMENT_FACILITIES'])
    stakeholders_scanned['healthcare_and_public_health'] = len(ci_stakeholders_by_type['CI_HEALTHCARE_AND_PUBLIC_HEALTH'])
    stakeholders_scanned['information_technology'] = len(ci_stakeholders_by_type['CI_INFORMATION_TECHNOLOGY'])
    stakeholders_scanned['nuclear_reactors_materials_and_waste'] = len(ci_stakeholders_by_type['CI_NUCLEAR_REACTORS_MATERIALS_AND_WASTE'])
    stakeholders_scanned['transportation_systems'] = len(ci_stakeholders_by_type['CI_TRANSPORTATION_SYSTEMS'])
    stakeholders_scanned['water_and_wastewater_systems'] = len(ci_stakeholders_by_type['CI_WATER_AND_WASTEWATER_SYSTEMS'])

    return stakeholders_scanned

def ticket_counts_by_fiscal_year(db, current_fy_start):
    fy_ticket_counts_by_year = dict()
    fy_ticket_count_totals = {'opened':0, 'closed':0}

    while True:
        next_fy_start = current_fy_start + relativedelta(years=1)
        # Tickets opened during the fiscal year
        tix_opened = db.TicketDoc.find({'source': 'nessus', 'time_opened':{'$gte':current_fy_start, '$lt':next_fy_start}, 'false_positive':False}).count()
        # Tickets open at any point during the fiscal year
        open_tix = db.TicketDoc.find({'source': 'nessus', '$or':[ {'$and': [{'time_opened':{'$gte':current_fy_start, '$lt':next_fy_start}}, {'false_positive':False}]},
                                              {'$and': [{'time_closed':{'$gte':current_fy_start, '$lt':next_fy_start}}, {'false_positive':False}]},
                                              {'$and': [{'time_opened':{'$lt':current_fy_start}}, {'open':True}, {'false_positive':False}]},
                                              {'$and': [{'time_opened':{'$lt':current_fy_start}}, {'open':False},
                                                        {'time_closed':{'$gte':next_fy_start}}, {'false_positive':False}]}
                                            ]}).count()
        # Tickets closed during the fiscal year
        tix_closed = db.TicketDoc.find({'source': 'nessus', 'time_closed':{'$gte':current_fy_start, '$lt':next_fy_start}, 'false_positive':False}).count()

        if tix_opened > 0:
            current_fiscal_year = str(current_fy_start.year + 1)
            fy_ticket_counts_by_year[current_fiscal_year] = dict()

            fy_ticket_counts_by_year[current_fiscal_year]['opened'] = tix_opened
            fy_ticket_count_totals['opened'] += tix_opened

            fy_ticket_counts_by_year[current_fiscal_year]['open'] = open_tix

            fy_ticket_counts_by_year[current_fiscal_year]['closed'] = tix_closed
            fy_ticket_count_totals['closed'] += tix_closed

            # Go back to the previous fiscal year and try again...
            current_fy_start = current_fy_start - relativedelta(years=1)
        else:
            return fy_ticket_counts_by_year, fy_ticket_count_totals

def all_time_opened_and_closed_breakdown(db):
    '''
    Total number of TicketDoc opened in CyHy since inception (as of current date/time)
    - Count of TicketDoc by Critical/High/Med/Low
    Total number of TicketDoc currently open in CyHy
    - Count of TicketDoc by Critical/High/Med/Low
    Total number of TicketDoc closed in CyHy since inception
    - Count of TicketDoc by Critical/High/Med/Low
    (Excluding False Positives)'''
    all_time_opened_and_closed = {'total_opened_since_inception':"{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False}).count())}
    all_time_opened_and_closed['total_opened_since_inception_critical'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':4}).count())
    all_time_opened_and_closed['total_opened_since_inception_high'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':3}).count())
    all_time_opened_and_closed['total_opened_since_inception_medium'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':2}).count())
    all_time_opened_and_closed['total_opened_since_inception_low'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':1}).count())

    all_time_opened_and_closed['currently_open'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'open':True}).count())
    all_time_opened_and_closed['currently_open_critical'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':4,'open':True}).count())
    all_time_opened_and_closed['currently_open_high'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':3,'open':True}).count())
    all_time_opened_and_closed['currently_open_medium'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':2,'open':True}).count())
    all_time_opened_and_closed['currently_open_low'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':1,'open':True}).count())

    all_time_opened_and_closed['total_closed_since_inception'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'open':False}).count())
    all_time_opened_and_closed['total_closed_since_inception_critical'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':4,'open':False}).count())
    all_time_opened_and_closed['total_closed_since_inception_high'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':3,'open':False}).count())
    all_time_opened_and_closed['total_closed_since_inception_medium'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':2,'open':False}).count())
    all_time_opened_and_closed['total_closed_since_inception_low'] = "{:,d}".format(db.TicketDoc.find({'source': 'nessus', 'false_positive':False,'details.severity':1,'open':False}).count())

    return all_time_opened_and_closed

def report(db, orgs, start, end):
    # opened during period
    opened_tix = list()
    opened_tix.append(db.tickets.find({'source': 'nessus', 'time_opened':{'$gte':start, '$lte':end}, 'false_positive': False}).count())
    opened_tix.append(db.tickets.find({'source': 'nessus', 'time_opened':{'$gte':start, '$lte':end}, 'owner': {'$in': orgs['FEDERAL']}, 'false_positive': False}).count())
    opened_tix.append(db.tickets.find({'source': 'nessus', 'time_opened':{'$gte':start, '$lte':end}, 'owner': {'$in': orgs['SLTT']}, 'false_positive': False}).count())
    opened_tix.append(db.tickets.find({'source': 'nessus', 'time_opened':{'$gte':start, '$lte':end}, 'owner': {'$in': orgs['PRIVATE']}, 'false_positive': False}).count())
    # closed during period
    closed_tix = list()
    closed_tix.append(db.tickets.find({'source': 'nessus', 'time_closed':{'$gte':start, '$lte':end}}).count())
    closed_tix.append(db.tickets.find({'source': 'nessus', 'time_closed':{'$gte':start, '$lte':end}, 'owner': {'$in': orgs['FEDERAL']}}).count())
    closed_tix.append(db.tickets.find({'source': 'nessus', 'time_closed':{'$gte':start, '$lte':end}, 'owner': {'$in': orgs['SLTT']}}).count())
    closed_tix.append(db.tickets.find({'source': 'nessus', 'time_closed':{'$gte':start, '$lte':end}, 'owner': {'$in': orgs['PRIVATE']}}).count())
    # reports generated during period
    reports = list()
    reports.append(db.reports.find({'source': 'nessus', 'report_types':REPORT_TYPE.CYHY, 'generated_time':{'$gte':start, '$lte':end}}).count())
    reports.append(db.reports.find({'source': 'nessus', 'report_types':REPORT_TYPE.CYHY, 'generated_time':{'$gte':start, '$lte':end}, 'owner': {'$in': orgs['FEDERAL']}}).count())
    reports.append(db.reports.find({'source': 'nessus', 'report_types':REPORT_TYPE.CYHY, 'generated_time':{'$gte':start, '$lte':end}, 'owner': {'$in': orgs['SLTT']}}).count())
    reports.append(db.reports.find({'source': 'nessus', 'report_types':REPORT_TYPE.CYHY, 'generated_time':{'$gte':start, '$lte':end}, 'owner': {'$in': orgs['PRIVATE']}}).count())
    return opened_tix, closed_tix, reports

def total_open(db, orgs):
    open_non_FP_tix = dict()
    open_non_FP_tix['total'] = '{:,}'.format(db.tickets.find({'open':True, 'source': 'nessus', 'false_positive': False}).count())
    open_non_FP_tix['federal'] = '{:,}'.format(db.tickets.find({'open':True, 'source': 'nessus', 'owner': {'$in': orgs['FEDERAL']}, 'false_positive': False}).count())
    open_non_FP_tix['SLTT'] = '{:,}'.format(db.tickets.find({'open':True, 'source': 'nessus', 'owner': {'$in': orgs['SLTT']}, 'false_positive': False}).count())
    open_non_FP_tix['private'] = '{:,}'.format(db.tickets.find({'open':True, 'source': 'nessus', 'owner': {'$in': orgs['PRIVATE']}, 'false_positive': False}).count())

    open_FP_tix = dict()
    open_FP_tix['total'] = '{:,}'.format(db.TicketDoc.find({'open':True, 'source': 'nessus', 'false_positive': True}).count())
    open_FP_tix['federal'] = '{:,}'.format(db.tickets.find({'open':True, 'source': 'nessus', 'owner': {'$in': orgs['FEDERAL']}, 'false_positive': True}).count())
    open_FP_tix['SLTT'] = '{:,}'.format(db.tickets.find({'open':True, 'source': 'nessus', 'owner': {'$in': orgs['SLTT']}, 'false_positive': True}).count())
    open_FP_tix['private'] = '{:,}'.format(db.tickets.find({'open':True, 'source': 'nessus', 'owner': {'$in': orgs['PRIVATE']}, 'false_positive': True}).count())
    return open_non_FP_tix, open_FP_tix

def print_activity(stats, title, start, end):
    print '\n%s (%s - %s):' % (title, start, end)
    print '\tTickets Opened:', stats['opened']
    print '\t\tFederal:', stats['fedOpened']
    print '\t\tSLTT:', stats['SLTTOpened']
    print '\t\tPrivate:', stats['privOpened']
    print '\tTickets Closed:', stats['closed']
    print '\t\tFederal:', stats['fedClosed']
    print '\t\tSLTT:', stats['SLTTClosed']
    print '\t\tPrivate:', stats['privClosed']
    print '\tCyHy Reports Generated:', stats['reports']
    print '\t\tFederal:', stats['fedReports']
    print '\t\tSLTT:', stats['SLTTReports']
    print '\t\tPrivate:', stats['privReports']

def return_activity(db, orgs, title, start, end):
    opened_tix, closed_tix, reports = report(db, orgs, start, end)
    detail = {'start': str(start)}
    detail['end'] = str(end)
    detail['opened'] = '{:,}'.format(opened_tix[0])
    detail['fedOpened'] = '{:,}'.format(opened_tix[1])
    detail['SLTTOpened'] = '{:,}'.format(opened_tix[2])
    detail['privOpened'] = '{:,}'.format(opened_tix[3])
    detail['closed'] = '{:,}'.format(closed_tix[0])
    detail['fedClosed'] = '{:,}'.format(closed_tix[1])
    detail['SLTTClosed'] = '{:,}'.format(closed_tix[2])
    detail['privClosed'] = '{:,}'.format(closed_tix[3])
    detail['reports'] = '{:,}'.format(reports[0])
    detail['fedReports'] = '{:,}'.format(reports[1])
    detail['SLTTReports'] = '{:,}'.format(reports[2])
    detail['privReports'] = '{:,}'.format(reports[3])
    return detail

def get_stats(db):
    orgs = db.RequestDoc.get_owner_types(as_lists=True, stakeholders_only=False, include_retired=True)
    orgs['SLTT'] = orgs[AGENCY_TYPE.STATE] + orgs[AGENCY_TYPE.LOCAL] + orgs[AGENCY_TYPE.TRIBAL] + orgs[AGENCY_TYPE.TERRITORIAL]
    now = util.utcnow()
    rd = util.report_dates(now)

    ticket = dict()
    ticket['open_non_FP_tix'], ticket['open_FP_tix'] = total_open(db, orgs)
    ticket['FY_ticket_counts_by_year'], ticket['FY_ticket_count_totals'] = ticket_counts_by_fiscal_year(db, rd['fy_start'])
    ticket['currentFYactivity'] = return_activity(db, orgs, 'Current FY Activity', rd['fy_start'], now)
    ticket['previousFYactivity'] = return_activity(db, orgs, 'Previous FY Activity', rd['prev_fy_start'], rd['prev_fy_end'])
    ticket['currentMonthActivity'] = return_activity(db, orgs, 'Current Month Activity', rd['month_start'], now)
    ticket['previousMonthActivity'] = return_activity(db, orgs, 'Previous Month Activity', rd['prev_month_start'], rd['prev_month_end'])
    ticket['currentWeekActivity'] = return_activity(db, orgs, 'Current Week Activity', rd['week_start'], now)
    ticket['previousWeekActivity'] = return_activity(db, orgs, 'Previous Week Activity', rd['prev_week_start'], rd['prev_week_end'])
    ticket['stakeholders_scanned'] = scanning_breakdown(db)
    ticket['all_time_tickets'] = all_time_opened_and_closed_breakdown(db)
    return rd, ticket

def main():
    args = docopt(__doc__, version='v0.0.1')
    db = database.db_from_config(args['--section'])

    rd, stats = get_stats(db)

    print 'Currently-Open Non-False-Positive Tickets:', stats['open_non_FP_tix']['total']
    print '\tFederal:', stats['open_non_FP_tix']['federal']
    print '\tSLTT:', stats['open_non_FP_tix']['SLTT']
    print '\tPrivate:', stats['open_non_FP_tix']['private']
    print 'Currently-Open False-Positive Tickets:', stats['open_FP_tix']['total']
    print '\tFederal:', stats['open_FP_tix']['federal']
    print '\tSLTT:', stats['open_FP_tix']['SLTT']
    print '\tPrivate:', stats['open_FP_tix']['private']
    print '\nData below does not include False-Positive tickets'

    FY_ticket_counts_by_year = stats['FY_ticket_counts_by_year'].items()
    FY_ticket_counts_by_year.sort()
    print '\nFiscal Year   Tickets Opened   Tickets Open   Tickets Closed'
    for fiscal_year, ticket_counts in FY_ticket_counts_by_year:
        print '{:>11}   {:>14,}   {:>12,}   {:>14,}'.format(fiscal_year, ticket_counts['opened'], ticket_counts['open'], ticket_counts['closed'])
    print '{:>11}   {:>14,}   {:>12}   {:>14,}'.format('TOTAL', stats['FY_ticket_count_totals']['opened'], ' ', stats['FY_ticket_count_totals']['closed'])

    print_activity(stats['currentFYactivity'], 'Current FY Activity', rd['fy_start'], rd['now'])
    print_activity(stats['previousFYactivity'], 'Previous FY Activity', rd['prev_fy_start'], rd['prev_fy_end'])
    print_activity(stats['currentMonthActivity'], 'Current Month Activity', rd['month_start'], rd['now'])
    print_activity(stats['previousMonthActivity'], 'Previous Month Activity', rd['prev_month_start'], rd['prev_month_end'])
    print_activity(stats['currentWeekActivity'], 'Current Week Activity', rd['week_start'], rd['now'])
    print_activity(stats['previousWeekActivity'], 'Previous Week Activity', rd['prev_week_start'], rd['prev_week_end'])

if __name__=='__main__':
    main()
