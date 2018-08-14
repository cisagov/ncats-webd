import json
import re
from collections import defaultdict, OrderedDict

from flask import Blueprint, render_template, abort, current_app, request, Response
from flask_socketio import send, emit
from bson.objectid import ObjectId
from dateutil import parser, tz

import datetime
from pandas import Series, DataFrame
import pandas as pd
import numpy as np
import schedule

from cyhy.util import util
from cyhy.db import database
from ncats_webd.common import cache, socketio, catch_exceptions

#from trepan.api import debug

BLUEPRINT_NAME = 'cybex'
bp = Blueprint(BLUEPRINT_NAME, __name__,
               template_folder='templates',
               static_folder='static')

REFRESH_INTERVAL = 600
#GRAPH_DAYS = 365            # Number of days of data to show in the age history graphs
#GRAPH_START_DATE = (util.utcnow() - datetime.timedelta(days=GRAPH_DAYS)).replace(hour=0, minute=0, second=0, microsecond=0)
GRAPH_START_DATE = util.time_to_utc(parser.parse('20150521'))
GRAPH_BUCKET_CUTOFF_DAYS = 30    # Bucket divider for age history graphs
CRITICAL_HISTOGRAM_CUTOFF_DAYS = 180
HIGH_HISTOGRAM_CUTOFF_DAYS = 360
CRITICAL_SEVERITY = 4
HIGH_SEVERITY = 3
TICKETS_CLOSED_PAST_DAYS = 30
data_pusher = None

#import IPython; IPython.embed() #<<< BREAKPOINT >>>

###############################################################################
#  Server side event generation
###############################################################################

@bp.before_app_first_request
def schedule_broadcaster():
    def job():
        broadcast_cybex_update()
    schedule.every(REFRESH_INTERVAL + 1).seconds.do(job)

###############################################################################
#  Data Access
###############################################################################

def get_open_tickets_dataframe(ticket_severity):
    now = util.utcnow()
    first_report_time_cache = dict()     # Cache generated_time of first report for each ticket
    fed_executive_owners = current_app.db.RequestDoc.get_all_descendants('EXECUTIVE')
    tix = current_app.db.TicketDoc.find({'details.severity':ticket_severity, 'false_positive':False, 'owner':{'$in':fed_executive_owners}, 'open':True}, {'_id':False, 'owner':True, 'time_opened':True, 'ip':True, 'port':True, 'details.name':True, 'details.cve':True, 'snapshots':True})
    tix = list(tix)
    for x in tix:
        x.update(x['details'])
        del(x['details'])
        x['days_since_first_detected'] = (now - x['time_opened']).total_seconds() / (60*60*24)
        x['first_reported'] = x['days_since_first_reported'] = x['days_to_report'] = None
        if x.get('snapshots'):
            first_snapshot_id = x['snapshots'][0]
            first_report_time = first_report_time_cache.get(first_snapshot_id)
            if not first_report_time:
                # Not found in the cache, so make a database call
                first_report = current_app.db.reports.find_one({'snapshot_oid':first_snapshot_id})
                if first_report:
                    first_report_time = first_report.get('generated_time')
                    first_report_time_cache[first_snapshot_id] = first_report_time
            if first_report_time:
                x['first_reported'] = first_report_time
                x['days_since_first_reported'] = (now - x['first_reported']).total_seconds() / (60*60*24)
                x['days_to_report'] = x['days_since_first_detected'] - x['days_since_first_reported']
            del(x['snapshots'])

    df = DataFrame(tix)
    if not df.empty:
        df.sort_values(by='days_since_first_detected', ascending=False, inplace=True)
    return df

def get_closed_tickets_dataframe(ticket_severity):
    closed_since_date = util.utcnow() - datetime.timedelta(days=TICKETS_CLOSED_PAST_DAYS)
    fed_executive_owners = current_app.db.RequestDoc.get_all_descendants('EXECUTIVE')
    tix = current_app.db.TicketDoc.find({'time_closed':{'$gte':closed_since_date}, 'details.severity':ticket_severity, 'owner':{'$in':fed_executive_owners}, 'open':False}, {'_id':False, 'owner':True, 'time_opened':True, 'time_closed':True, 'ip':True, 'port':True, 'details.name':True, 'details.cve':True})
    tix = list(tix)
    for x in tix:
        x.update(x['details'])
        del(x['details'])
    df = DataFrame(tix)
    if not df.empty:
        df['days_to_close'] = (df.time_closed - df.time_opened).apply(lambda x : x.total_seconds()/86400.0).round(1)
        df.sort_values(by='time_closed', ascending=True, inplace=True)
    return df

def get_cybex_dataframe(start_date, ticket_severity):
    now = util.utcnow()
    tomorrow = now + datetime.timedelta(days=1)
    days_to_graph = pd.to_datetime(pd.date_range(start_date, now), utc=True)
    fed_executive_owners = current_app.db.RequestDoc.get_all_descendants('EXECUTIVE')

    # Calculate Buckets
    tix = current_app.db.TicketDoc.find({'details.severity':ticket_severity, 'false_positive':False, 'owner':{'$in':fed_executive_owners},
                            '$or':[{'time_closed':{'$gte':start_date}}, {'time_closed':None}]},
                            {'_id':False, 'time_opened':True, 'time_closed':True})
    tix = list(tix)
    df = DataFrame(tix)
    results_df = DataFrame(index=days_to_graph, columns=['young','old','total'])
    if not df.empty:
        df.time_closed = df.time_closed.fillna(tomorrow)        # for accounting purposes, say all open tix will close tomorrow
        # convert times to datetime64
        df.time_closed = pd.to_datetime(df.time_closed, utc=True)
        df.time_opened = pd.to_datetime(df.time_opened, utc=True)

        old_delta = np.timedelta64(GRAPH_BUCKET_CUTOFF_DAYS, 'D')

        for start_of_day, values in results_df.iterrows():
            end_of_day = start_of_day + np.timedelta64(1, 'D') - np.timedelta64(1, 'ns')
            open_on_day_mask = (df.time_opened <= end_of_day) & (df.time_closed > start_of_day)
            age_on_date = start_of_day - df.time_opened
            age_on_date_masked = age_on_date.mask(open_on_day_mask == False)
            values['total'] = open_on_day_mask.value_counts().get(True, 0)
            values['young'] = (age_on_date_masked < old_delta).value_counts().get(True, 0)
            values['old'] = (age_on_date_masked >= old_delta).value_counts().get(True, 0)
    return results_df

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_open_tickets(ticket_severity):
    results_df = get_open_tickets_dataframe(ticket_severity)
    results = results_df.to_dict('records')
    return json.dumps(results, default=util.custom_json_handler)

@cache.memoize(timeout=REFRESH_INTERVAL)
def csv_get_open_tickets(ticket_severity):
    if ticket_severity == CRITICAL_SEVERITY:
        severity_name = '_critical'
    elif ticket_severity == HIGH_SEVERITY:
        severity_name = '_high'
    else:
        severity_name = ''
    results_df = get_open_tickets_dataframe(ticket_severity)
    if not results_df.empty:
        #TODO date_format param not getting picked up.  Processing manually with apply
        results_df['time_opened'] = results_df['time_opened'].apply(lambda x : x.strftime('%Y-%m-%d %H:%M:%S')) # excel crap
        results_df['first_reported'] = results_df['first_reported'].apply(lambda x : x.strftime('%Y-%m-%d %H:%M:%S') if type(x) == pd.Timestamp else None)
        # Round values for 'days' fields to 1 decimal place
        results_df['days_since_first_detected'] = results_df['days_since_first_detected'].round(decimals=1)
        results_df['days_since_first_reported'] = results_df['days_since_first_reported'].round(decimals=1)
        results_df['days_to_report'] = results_df['days_to_report'].round(decimals=1)
        response = Response(results_df.to_csv(index=False, date_format='%Y-%m-%d %H:%M:%S', columns=['owner', 'ip', 'port', 'name', 'cve', 'time_opened', 'days_since_first_detected', 'first_reported', 'days_since_first_reported', 'days_to_report']), mimetype='text/csv')
    else:
        response = Response('', mimetype='text/csv')
    response.headers["Content-Disposition"] = "attachment; filename=cybex_open_tickets{!s}_{!s}.csv".format(severity_name, util.utcnow().strftime('%Y%m%d'))
    return response

@cache.memoize(timeout=REFRESH_INTERVAL)
def csv_get_closed_tickets(ticket_severity):
    if ticket_severity == CRITICAL_SEVERITY:
        severity_name = '_critical'
    elif ticket_severity == HIGH_SEVERITY:
        severity_name = '_high'
    else:
        severity_name = ''
    results_df = get_closed_tickets_dataframe(ticket_severity)
    if not results_df.empty:
        #TODO date_format param not getting picked up.  Processing manually with apply
        results_df['time_opened'] = results_df['time_opened'].apply(lambda x : x.strftime('%Y-%m-%d %H:%M:%S')) # excel crap
        results_df['time_closed'] = results_df['time_closed'].apply(lambda x : x.strftime('%Y-%m-%d %H:%M:%S')) # excel crap
        response = Response(results_df.to_csv(index=False, date_format='%Y-%m-%d %H:%M:%S', columns=['owner', 'ip', 'port', 'name', 'cve', 'time_opened', 'time_closed', 'days_to_close']), mimetype='text/csv')
    else:
        response = Response('', mimetype='text/csv')
    response.headers["Content-Disposition"] = "attachment; filename=cybex_closed_tickets{!s}_past_{!s}_days_{!s}.csv".format(severity_name, TICKETS_CLOSED_PAST_DAYS, util.utcnow().strftime('%Y%m%d'))
    return response

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_cybex_data(start_date, ticket_severity):
    results_df = get_cybex_dataframe(start_date, ticket_severity)
    # create json output
    results = OrderedDict() # the order matters to c3js
    results['x'] = [x.strftime('%Y-%m-%d') for x in results_df.index]
    results['young'] = list(results_df.young)
    results['old'] = list(results_df.old)
    results['total'] = list(results_df.total)
    return json.dumps(results, default=util.custom_json_handler)

@cache.memoize(timeout=REFRESH_INTERVAL)
def csv_get_cybex_data(start_date, ticket_severity):
    if ticket_severity == CRITICAL_SEVERITY:
        severity_name = '_critical'
    elif ticket_severity == HIGH_SEVERITY:
        severity_name = '_high'
    else:
        severity_name = ''
    results_df = get_cybex_dataframe(start_date, ticket_severity)
    results_df.index.name = 'date'
    results_df.columns = ['< 30 days','> 30 days','total']
    response = Response(results_df.to_csv(), mimetype='text/csv')
    response.headers["Content-Disposition"] = "attachment; filename=cybex_graph{!s}_{!s}.csv".format(severity_name, util.utcnow().strftime('%Y%m%d'))
    return response

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_cybex_histogram_data(ticket_severity, max_age_cutoff=None):
    results_df = get_open_tickets_dataframe(ticket_severity)
    if results_df.empty == True:
        results = {'age':[]}
        return json.dumps(results, default=util.custom_json_handler)
    s = np.floor(results_df.days_since_first_detected)     # lop off any decimals so we can bucket appropriately
    oldest = int(s.max())
    s2 = s.value_counts().reindex(range(oldest+1)).fillna(0)
    results = OrderedDict() # the order matters to c3js
    if max_age_cutoff:
        s3 = s2[:max_age_cutoff]    # trim the list to the first max_age_cutoff entries
        s3['{!s}+'.format(max_age_cutoff)] = s2[max_age_cutoff:].sum()  # sum the rest of the values and put at the end of the dataset
        results['age'] = list(s3)
    else:
        results['age'] = list(s2)
    results['age'] += [0.0, 0.0]    # add 2 extra empty items so max value in histogram renders more visibly on screen
    return json.dumps(results, default=util.custom_json_handler)


###############################################################################
#  Utils
###############################################################################


###############################################################################
#  Routes
###############################################################################

@bp.route('/')
def cybex():
    # data request
    if request.args.has_key('j1'):
        return json_get_cybex_data(GRAPH_START_DATE, CRITICAL_SEVERITY)
    elif request.args.has_key('c1'):
        return csv_get_cybex_data(GRAPH_START_DATE, CRITICAL_SEVERITY)
    elif request.args.has_key('j2'):
        return json_get_open_tickets(CRITICAL_SEVERITY)
    elif request.args.has_key('c2'):
        return csv_get_open_tickets(CRITICAL_SEVERITY)
    elif request.args.has_key('c3'):
        return csv_get_closed_tickets(CRITICAL_SEVERITY)
    elif request.args.has_key('j3'):
        return json_get_cybex_histogram_data(CRITICAL_SEVERITY, CRITICAL_HISTOGRAM_CUTOFF_DAYS)
    elif request.args.has_key('j4'):
        return json_get_cybex_data(GRAPH_START_DATE, HIGH_SEVERITY)
    elif request.args.has_key('c4'):
        return csv_get_cybex_data(GRAPH_START_DATE, HIGH_SEVERITY)
    elif request.args.has_key('j5'):
        return json_get_open_tickets(HIGH_SEVERITY)
    elif request.args.has_key('c5'):
        return csv_get_open_tickets(HIGH_SEVERITY)
    elif request.args.has_key('c6'):
        return csv_get_closed_tickets(HIGH_SEVERITY)
    elif request.args.has_key('j6'):
        return json_get_cybex_histogram_data(HIGH_SEVERITY, HIGH_HISTOGRAM_CUTOFF_DAYS)

    # template request
    return render_template('cybex.html')

@bp.route('/chart1')
def cybex_naked_chart1():
    return render_template('naked_cybex_chart1.html')

@bp.route('/chart2')
def cybex_naked_chart2():
    return render_template('naked_cybex_chart2.html')

@bp.route('/chart3')
def cybex_naked_chart3():
    return render_template('naked_cybex_chart3.html')

@bp.route('/chart4')
def cybex_naked_chart4():
    return render_template('naked_cybex_chart4.html')

###############################################################################
#  Socket.io Handlers
###############################################################################

@socketio.on('cybex_latest', namespace='/cyhy')
def latest_queues():
    current_app.logger.info('client requested latest Cyber Exposure data')
    broadcast_cybex_update(False)

###############################################################################
#  Socket.io Senders
###############################################################################

def broadcast_cybex_update(broadcast=True):
    chart1_data = json_get_cybex_data(GRAPH_START_DATE, CRITICAL_SEVERITY)
    chart2_data = json_get_cybex_histogram_data(CRITICAL_SEVERITY, CRITICAL_HISTOGRAM_CUTOFF_DAYS)
    chart3_data = json_get_cybex_data(GRAPH_START_DATE, HIGH_SEVERITY)
    chart4_data = json_get_cybex_histogram_data(HIGH_SEVERITY, HIGH_HISTOGRAM_CUTOFF_DAYS)
    data = {'cybex_chart1':chart1_data, 'cybex_chart2':chart2_data, 'cybex_chart3':chart3_data, 'cybex_chart4':chart4_data}
    # Note: emit will json encode our object with json data.
    # so we need to call JSON.parse on the json string
    # to reconstitue the object client-side.
    if broadcast:
        socketio.emit('cybex_data_push', data, namespace='/cyhy', room='cybex')
    else: # reply to latest request
        emit('cybex_data_push', data, namespace='/cyhy')
