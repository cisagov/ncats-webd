import json
import re
import time
import datetime
from collections import deque

from flask import Blueprint, render_template, abort, current_app, request
from flask_socketio import send, emit
from bson.objectid import ObjectId
import schedule

from cyhy.util import util
from cyhy.db import database
from ncats_webd.common import cache, socketio, catch_exceptions
from ncats_webd.queries import DashboardQueries

#import IPython; IPython.embed() #<<< BREAKPOINT >>>

BLUEPRINT_NAME = 'dashboard'
bp = Blueprint(BLUEPRINT_NAME, __name__,
               template_folder='templates',
               static_folder='static')

REFRESH_INTERVAL = 30 * 60
OID_RE = re.compile(r'^[0-9a-f]{24}$')
TID_RE = re.compile(r'^[/A-Za-z0-9]+$')
SOURCE_ID_RE = re.compile(r'^nessus:[0-9]+$')
ticket_feed = None

class TicketFeed(object):
    #TODO decrease sleep_time after testing query load on db
    def __init__(self, db, emitter, logger, sleep_time=300, history_size=100):
        self.__db = db
        self.__emitter = emitter
        self.__logger = logger
        self.__sleep_time = sleep_time
        self.__since = util.utcnow() - datetime.timedelta(minutes=30)
        self.__history = deque(maxlen=history_size)
        schedule.every(sleep_time).seconds.do(self.__work)

    @catch_exceptions
    def __work(self):
        self.__logger.debug('checking for updated tickets')
        new_tickets = self.__check_database()
        if new_tickets:
            self.__logger.debug('found %d updated tickets' % len(new_tickets))
            self.__history.extend(new_tickets)
            self.__emitter(new_tickets)
        else:
            self.__logger.debug('no updated tickets found')

    def __check_database(self):
        now = util.utcnow()
        tickets = self.__db.tickets.find({'last_change':{'$gt':self.__since}},
                                         {'_id':1,'owner':1, 'details':1, 'events.action':1, 'events':{'$slice':-1}}) \
                                         .sort([('last_change',-1)])
        tickets = list(tickets)
        for x in tickets: # convert _ids to string since we can't set custom json handler
            x['_id'] = str(x['_id'])
        self.__since = now
        return tickets

    @property
    def history(self):
        return list(self.__history)


###############################################################################
#  Server side event generation
###############################################################################

@bp.before_app_first_request
def start_background_thread():
    global ticket_feed
    if ticket_feed is None:
        ticket_feed = TicketFeed(current_app.db, broadcast_new_tickets, current_app.logger)
    #TODO: Probably throwing exception quietly
    @catch_exceptions
    def job():
        broadcast_overall_metrics()
        broadcast_ticket_severity_counts()
        broadcast_election_metrics()
        broadcast_election_ticket_severity_counts()
    schedule.every(60).seconds.do(job)

###############################################################################
#  Data Access
###############################################################################
def first_seen_ticket_counts():
    return [
           {'$match': {'false_positive':False}},
           {'$group': {'_id': {'source':'$source',
                               'source_id':'$source_id'
                              },
                       'first_seen':{'$min':'$time_opened'},
                       'open_count':{'$sum':{'$cond':[{'$eq':['$open',True]}, 1, 0]}},
                       'closed_count':{'$sum':{'$cond':[{'$eq':['$open',False]}, 1, 0]}},
                       'total':{'$sum':1},
                       'details':{'$first':'$details'},
                      }
           },
           {'$sort': {'first_seen':-1}}
           ], database.TICKET_COLLECTION

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_first_seen_ticket_counts():
    cursor = database.run_pipeline_cursor(first_seen_ticket_counts(), current_app.db)
    counts = list(cursor)
    database.id_expand(counts)
    return counts

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_ticket_severity_counts():
    stakeholders = DashboardQueries.build_stakeholder_list(current_app.db)
    sorted_ticket_data = DashboardQueries.get_ticket_severity_counts(current_app.db, current_app.db.requests.find({'stakeholder':True}))
    return json.dumps(sorted_ticket_data, default=util.custom_json_handler)

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_overall_metrics():
    stakeholders = DashboardQueries.build_stakeholder_list(current_app.db)
    results = DashboardQueries.get_overall_metrics(current_app.db, stakeholders)
    return json.dumps(results, default=util.custom_json_handler)

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_election_metrics():
    election_stakeholders = DashboardQueries.build_election_list(current_app.db)
    results = DashboardQueries.get_election_metrics(current_app.db)
    return json.dumps(results, default=util.custom_json_handler)

@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_election_ticket_severity_counts():
    election_stakeholders = DashboardQueries.build_election_list(current_app.db)
    sorted_ticket_data = DashboardQueries.get_ticket_severity_counts(current_app.db, current_app.db.requests.find({'_id':{'$in':election_stakeholders}}))
    return json.dumps(sorted_ticket_data, default=util.custom_json_handler)

###############################################################################
#  Util
###############################################################################

def is_valid_oid(dirty_input):
    return OID_RE.match(dirty_input)

def is_valid_tid(dirty_input):
    return TID_RE.match(dirty_input)

def is_valid_source_id(dirty_input):
    return SOURCE_ID_RE.match(dirty_input)

def atom(doc_type, template, oid, is_text_id=False):
    if is_text_id:
        if not is_valid_tid(oid):
            abort(400) # Bad Request
        _id = oid
    else:
        if not is_valid_oid(oid):
            abort(400) # Bad Request
        _id = ObjectId(oid)

    # data request
    if request.args.has_key('j'):
        doc = doc_type.find_one({'_id':_id})
        return json.dumps(doc, default=util.custom_json_handler)

    # template request
    return render_template(template)


###############################################################################
#  Routes
###############################################################################

@bp.route('/')
def dashboard():
    # template request
    return render_template('dashboard-2.html', refresh_interval=REFRESH_INTERVAL/2)

@bp.route('/orig')
def dashboard2():
    # data request
    if request.args.has_key('j'):
        counts = json_get_ticket_counts()
        return json.dumps(counts, default=util.custom_json_handler)

    # template request
    return render_template('dashboard-1.html', refresh_interval=REFRESH_INTERVAL/2)

@bp.route('/firstseen')
def firstseen():
    # data request
    if request.args.has_key('j'):
        counts = json_get_first_seen_ticket_counts()
        return json.dumps(counts, default=util.custom_json_handler)

    # template request
    return render_template('firstseen.html', refresh_interval=REFRESH_INTERVAL/2)

@bp.route('/o/<oid>')
def owner(oid):
    return atom(current_app.db.RequestDoc, 'owner.html', oid, is_text_id=True)

@bp.route('/t/<oid>')
def ticket(oid):
    return atom(current_app.db.TicketDoc, 'ticket.html', oid)

@bp.route('/v/<oid>')
def vulnscan(oid):
    return atom(current_app.db.VulnScanDoc, 'vulnscan.html', oid)

@bp.route('/h/<oid>')
def hostscan(oid):
    return atom(current_app.db.HostScanDoc, 'hostscan.html', oid)

@bp.route('/p/<oid>')
def portscan(oid):
    return atom(current_app.db.PortScanDoc, 'portscan.html', oid)

@bp.route('/ss/<oid>')
def snapshot(oid):
    return atom(current_app.db.SnapshotDoc, 'snapshot.html', oid)

@bp.route('/tq/<source_id>')
def ticket_query_source(source_id):
    if not is_valid_source_id(source_id):
            abort(400) # Bad Request
    source, source_id = source_id.split(':')
    doc = list(current_app.db.TicketDoc.find({'source':source,'source_id':int(source_id)}))
    return json.dumps(doc, default=util.custom_json_handler)

@bp.route('/tq/<owner_id>/<source_id>')
def ticket_query_owner_source(owner_id, source_id):
    return atom(current_app.db.SnapshotDoc, 'snapshot.html', oid)


###############################################################################
#  Socket.io Handlers
###############################################################################

@socketio.on('history', namespace='/cyhy')
def history_event(count=100):
    print('Client requested history')
    #send(json, json=True) #unnamed event
    emit('historic_tickets', ticket_feed.history[-count:]) #named event

@socketio.on('overall_metrics_latest', namespace='/cyhy')
def latest_overall_metrics_event():
    current_app.logger.info('client requested overall metrics data')
    emit('overall_metrics', {'data':json_get_overall_metrics()})

@socketio.on('ticket_severity_counts_latest', namespace='/cyhy')
def latest_ticket_severity_counts_event():
    current_app.logger.info('client requested ticket severity counts data')
    emit('ticket_severity_counts', {'data':json_get_ticket_severity_counts()})

@socketio.on('election_metrics_latest', namespace='/cyhy')
def latest_overall_metrics_event():
    current_app.logger.info('client requested election metrics data')
    emit('election_metrics', {'data':json_get_election_metrics()})

@socketio.on('election_ticket_severity_counts_latest', namespace='/cyhy')
def latest_ticket_severity_counts_event():
    current_app.logger.info('client requested election ticket severity counts data')
    emit('election_ticket_severity_counts', {'data':json_get_election_ticket_severity_counts()})

###############################################################################
#  Socket.io Senders
###############################################################################

def broadcast_new_tickets(tickets):
    current_app.logger.debug('broadcasting new tickets')
    socketio.emit('new_tickets', tickets, namespace='/cyhy', room='ticket_log')

def broadcast_overall_metrics():
    current_app.logger.debug('broadcasting overall metrics')
    overall_metrics = json_get_overall_metrics()
    socketio.emit('overall_metrics', {'data':overall_metrics}, namespace='/cyhy', room='overall_metrics')

def broadcast_ticket_severity_counts():
    current_app.logger.debug('broadcasting ticket severity counts')
    ticket_severity_counts = json_get_ticket_severity_counts()
    socketio.emit('ticket_severity_counts', {'data':ticket_severity_counts}, namespace='/cyhy', room='ticket_severity_counts')

def broadcast_election_metrics():
    current_app.logger.debug('broadcasting election metrics')
    election_metrics = json_get_election_metrics()
    socketio.emit('election_metrics', {'data':election_metrics}, namespace='/cyhy', room='election_metrics')

def broadcast_election_ticket_severity_counts():
    current_app.logger.debug('broadcasting election ticket severity counts')
    ticket_severity_counts = json_get_election_ticket_severity_counts()
    socketio.emit('eleciton_ticket_severity_counts', {'data':ticket_severity_counts}, namespace='/cyhy', room='election_ticket_severity_counts')
