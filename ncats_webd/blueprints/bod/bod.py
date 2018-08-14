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

BLUEPRINT_NAME = 'bod'
bp = Blueprint(BLUEPRINT_NAME, __name__,
               template_folder='templates',
               static_folder='static')

REFRESH_INTERVAL = 300
BOD_START_DATE = parser.parse('2015-05-21T00:00:00').replace(tzinfo=tz.tzutc())
# NOTE: We should be able to just use parser.parse('2015-05-21T00:00:00Z') and get tzinfo=tzutc(), but on our blades where the local timezone
#       is set to UTC, it was being stored as tzinfo=tzlocal(), which threw an error when comparing to other timestamps where tzinfo=tzutc()
BOD_CUTOFF_1 = 30
BOD_CUTOFF_2 = 60
data_pusher = None

#import IPython; IPython.embed() #<<< BREAKPOINT >>>

###############################################################################
#  Server side event generation
###############################################################################

@bp.before_app_first_request
def schedule_broadcaster():
    def job():
        broadcast_bod_update()
    schedule.every(REFRESH_INTERVAL + 1).seconds.do(job)

###############################################################################
#  Data Access
###############################################################################

def get_bod_open_tickets_dataframe(bod_start_date):
    bod_owners = current_app.db.RequestDoc.get_all_descendants('EXECUTIVE')
    tix = current_app.db.TicketDoc.find({'details.severity':4, 'false_positive':False, 'owner':{'$in':bod_owners}, 'open':True},
        {'_id':False, 'owner':True, 'time_opened':True, 'ip':True, 'port':True, 'details.name':True, 'details.cve':True})
    tix = list(tix)
    for x in tix:
        x.update(x['details'])
        del(x['details'])
    df = DataFrame(tix)
    if not df.empty:
        bsd_utc = pd.to_datetime(bod_start_date)                # Store bod_start_date as pandas Timestamp
        df['time_opened'] = df.time_opened.dt.tz_convert('UTC') # Mark df.time_opened as UTC
        df['bod_time_opened'] = df.time_opened.apply(lambda x, bsd_utc=bsd_utc: max(x, bsd_utc))
        now = pd.to_datetime(util.utcnow())                     # Store current UTC time as pandas Timestamp
        df['bod_age_td'] = now - df.bod_time_opened
        df['bod_age'] = df['bod_age_td'].astype('timedelta64[D]')
        del(df['bod_time_opened'])
        del(df['bod_age_td'])
        df.sort_values(by='bod_age', ascending=False, inplace=True)
    return df

def get_bod_dataframe(bod_start_date):
    now = util.utcnow()
    tomorrow = now + datetime.timedelta(days=1)
    days_of_the_bod = pd.to_datetime(pd.date_range(bod_start_date, now), utc=True)

    bod_owners = current_app.db.RequestDoc.get_all_descendants('EXECUTIVE')

    backlog_tix = current_app.db.TicketDoc.find({'details.severity':4, 'owner':{'$in':bod_owners},
                     'time_opened':{'$lte':bod_start_date}, 'false_positive':False,
                     '$or':[{'time_closed':{'$gte':bod_start_date}}, {'time_closed':None}] },
                     {'_id':False, 'time_closed':True})

    results_df = DataFrame(index=days_of_the_bod, columns=['young','mid','old','total'])
    backlog_tix = list(backlog_tix)
    df = DataFrame(backlog_tix)
    if not df.empty:
        df['tally'] = 1
        df.time_closed = df.time_closed.fillna(tomorrow) # assume they'll close tomorrow
        df.time_closed = df.time_closed.apply(pd.to_datetime) # if fillna is noop we have wrong types still

        df_backlog = df.set_index('time_closed')
        df_backlog = df_backlog.resample('1D').sum()

        df_backlog = df_backlog.reindex(days_of_the_bod) # does not include tomorrow
        df_backlog.tally = df_backlog.tally.fillna(0).astype(np.int)
        df_backlog['csum'] = df_backlog.tally.cumsum()
        df_backlog['remaining'] = len(backlog_tix) - df_backlog.csum
    else:
        df_backlog = DataFrame()
    # Calculate Buckets
    tix = current_app.db.TicketDoc.find({'details.severity':4, 'false_positive':False, 'owner':{'$in':bod_owners},
                            '$or':[{'time_closed':{'$gte':bod_start_date}}, {'time_closed':None}]},
                            {'_id':False, 'time_opened':True, 'time_closed':True})
    df = DataFrame(list(tix))
    if not df.empty:
        # Convert times to pandas Timestamp
        df.time_opened = pd.to_datetime(df.time_opened, utc=True)
        # For tickets that haven't closed yet, also set time_closed to tomorrow
        #df.time_closed = pd.to_datetime(df.time_closed.fillna(tomorrow), utc=True).dt.tz_localize('UTC')
        df.time_closed = pd.to_datetime(df.time_closed.fillna(tomorrow), utc=True).dt.tz_convert('UTC')
        bsd_utc = pd.to_datetime(bod_start_date)          # Store bod_start_date as pandas Timestamp
        df['bod_time_opened'] = df.time_opened.apply(lambda x, bsd_utc=bsd_utc: max(x, bsd_utc))
        df['bod_age'] = df.time_closed - df.bod_time_opened

        mid_delta = np.timedelta64(BOD_CUTOFF_1, 'D')
        old_delta = np.timedelta64(BOD_CUTOFF_2, 'D')

        for start_of_day, values in results_df.iterrows():
            end_of_day = start_of_day + np.timedelta64(1, 'D') - np.timedelta64(1, 'ns')
            open_on_day_mask = (df.time_opened <= end_of_day) & (df.time_closed > start_of_day)
            bod_age_on_date = start_of_day - df.bod_time_opened
            bod_age_on_date_masked = bod_age_on_date.mask(open_on_day_mask == False)
            values['total'] = open_on_day_mask.value_counts().get(True, 0)
            values['young'] = (bod_age_on_date_masked < mid_delta).value_counts().get(True, 0)
            values['mid'] = ((bod_age_on_date_masked >= mid_delta) &
                           (bod_age_on_date_masked < old_delta)).value_counts().get(True, 0)
            values['old'] = (bod_age_on_date_masked >= old_delta).value_counts().get(True, 0)

        if not df_backlog.empty:
            # combine previous calculations
            results_df['backlog'] = df_backlog.remaining
    return results_df

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_bod_open_tickets(bod_start_date):
    results_df = get_bod_open_tickets_dataframe(bod_start_date)
    results = results_df.to_dict('records')
    return json.dumps(results, default=util.custom_json_handler)

@cache.memoize(timeout=REFRESH_INTERVAL)
def csv_get_bod_open_tickets(bod_start_date):
    results_df = get_bod_open_tickets_dataframe(bod_start_date)
    #TODO date_format param not getting picked up.  Processing manually with apply
    results_df['time_opened'] = results_df['time_opened'].apply(lambda x : x.strftime('%Y-%m-%d %H:%M:%S')) # excel crap
    response = Response(results_df.to_csv(index=False, date_format='%Y-%m-%d %H:%M:%S'), mimetype='text/csv')
    response.headers["Content-Disposition"] = "attachment; filename=bod_tickets.csv"
    return response

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_bod_data(bod_start_date):
    results_df = get_bod_dataframe(bod_start_date)
    # create json output
    results = OrderedDict() # the order matters to c3js
    results['x'] = [x.strftime('%Y-%m-%d') for x in results_df.index]
    results['young'] = list(results_df.young)
    results['mid'] = list(results_df.mid)
    results['old'] = list(results_df.old)
    results['total'] = list(results_df.total)
    results['backlog'] = list(results_df.backlog)
    return json.dumps(results, default=util.custom_json_handler)

@cache.memoize(timeout=REFRESH_INTERVAL)
def csv_get_bod_data(bod_start_date):
    results_df = get_bod_dataframe(bod_start_date)
    results_df.index.name = 'date'
    results_df.columns = ['< 30 days','30-60 days','> 60 days','total','backlog']
    response = Response(results_df.to_csv(), mimetype='text/csv')
    response.headers["Content-Disposition"] = "attachment; filename=bod_graph.csv"
    return response

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_bod_histogram_data(bod_start_date):
    results_df = get_bod_open_tickets_dataframe(bod_start_date)
    if results_df.empty == True:
        return {}
    s = results_df.bod_age
    oldest = int(s.max())
    s2 = s.value_counts().reindex(range(oldest+1)).fillna(0)
    results = OrderedDict() # the order matters to c3js
    results['age'] = list(s2)
    return json.dumps(results, default=util.custom_json_handler)


###############################################################################
#  Utils
###############################################################################


###############################################################################
#  Routes
###############################################################################

@bp.route('/')
def bod():
    # data request
    if request.args.has_key('j1'):
        return json_get_bod_data(BOD_START_DATE)
    elif request.args.has_key('c1'):
        return csv_get_bod_data(BOD_START_DATE)
    elif request.args.has_key('j2'):
        return json_get_bod_open_tickets(BOD_START_DATE)
    elif request.args.has_key('c2'):
        return csv_get_bod_open_tickets(BOD_START_DATE)
    elif request.args.has_key('j3'):
        return json_get_bod_histogram_data(BOD_START_DATE)

    # template request
    return render_template('bod.html')

@bp.route('/chart1')
def bod_naked_chart1():
    return render_template('naked_bod_chart1.html')

@bp.route('/chart2')
def bod_naked_chart2():
    return render_template('naked_bod_chart2.html')

###############################################################################
#  Socket.io Handlers
###############################################################################

@socketio.on('bod_latest', namespace='/cyhy')
def latest_queues():
    current_app.logger.info('client requested latest bod data')
    broadcast_bod_update(False)

###############################################################################
#  Socket.io Senders
###############################################################################

def broadcast_bod_update(broadcast=True):
    chart1_data = json_get_bod_data(BOD_START_DATE)
    chart2_data = json_get_bod_histogram_data(BOD_START_DATE)
    data = {'bod_chart1':chart1_data, 'bod_chart2':chart2_data}
    # Note: emit will json encode our object with json data.
    # so we need to call JSON.parse on the json string
    # to reconstitue the object client-side.
    if broadcast:
        socketio.emit('bod_data_push', data, namespace='/cyhy', room='bod')
    else: # reply to latest request
        emit('bod_data_push', data, namespace='/cyhy')
