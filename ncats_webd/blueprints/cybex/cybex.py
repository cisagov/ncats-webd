from flask import Blueprint, render_template, abort, current_app, request, Response
from flask_socketio import send, emit
from bson.objectid import ObjectId
from dateutil import parser

import datetime
import schedule

from cyhy.util import util
from ncats_webd.common import cache, socketio, catch_exceptions
import ncats_webd.cybex_queries

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

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_open_tickets(ticket_severity):
    return ncats_webd.cybex_queries.json_get_open_tickets(current_app.db, ticket_severity)

@cache.memoize(timeout=REFRESH_INTERVAL)
def csv_get_open_tickets(ticket_severity):
    if ticket_severity == CRITICAL_SEVERITY:
        severity_name = '_critical'
    elif ticket_severity == HIGH_SEVERITY:
        severity_name = '_high'
    else:
        severity_name = ''

    csv = ncats_webd.cybex_queries.csv_get_open_tickets(current_app.db, ticket_severity)
    response = Response(csv, mimetype='text/csv')
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

    csv = ncats_webd.cybex_queries.csv_get_closed_tickets(current_app.db, ticket_severity)
    response = Response(csv, mimetype='text/csv')
    response.headers["Content-Disposition"] = "attachment; filename=cybex_closed_tickets{!s}_past_{!s}_days_{!s}.csv".format(severity_name, ncats_webd.cybex_queries.TICKETS_CLOSED_PAST_DAYS, util.utcnow().strftime('%Y%m%d'))
    return response

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_cybex_data(start_date, ticket_severity):
    return ncats_webd.cybex_queries.json_get_cybex_data(current_app.db, start_date, ticket_severity)

@cache.memoize(timeout=REFRESH_INTERVAL)
def csv_get_cybex_data(start_date, ticket_severity):
    if ticket_severity == CRITICAL_SEVERITY:
        severity_name = '_critical'
    elif ticket_severity == HIGH_SEVERITY:
        severity_name = '_high'
    else:
        severity_name = ''

    csv = ncats_webd.cybex_queries.csv_get_cybex_data(current_app.db, start_date, ticket_severity)
    response = Response(csv, mimetype='text/csv')
    response.headers["Content-Disposition"] = "attachment; filename=cybex_graph{!s}_{!s}.csv".format(severity_name, util.utcnow().strftime('%Y%m%d'))
    return response

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_cybex_histogram_data(ticket_severity, max_age_cutoff=None):
    return ncats_webd.cybex_queries.json_get_cybex_histogram_data(current_app.db, ticket_severity, max_age_cutoff)


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
