import json
from flask import Blueprint, render_template, abort, current_app, redirect, url_for, request

from cyhy.util import util
from ncats_webd.common import cache
from ncats_webd.queries import MapQueries

BLUEPRINT_NAME = 'maps'
bp = Blueprint(BLUEPRINT_NAME, __name__,
               template_folder='templates',
               static_folder='static')

###############################################################################
#  Data Access
###############################################################################

@cache.memoize(timeout=300)
def json_get_loc_severity(severity=None):
    results = MapQueries.get_open_ticket_loc_by_severity(current_app.db, severity)
    return json.dumps(results, default=util.custom_json_handler)

@cache.memoize(timeout=30)
def json_get_running():
    results = MapQueries.get_running_ips(current_app.db)
    return json.dumps(results, default=util.custom_json_handler)

@cache.memoize(timeout=3600)
def json_get_ip_locs():
    results = MapQueries.get_host_locations(current_app.db)
    return json.dumps(results, default=util.custom_json_handler)

###############################################################################
#  Routes
###############################################################################

@bp.route('/')
def root():
    return redirect(url_for(BLUEPRINT_NAME+'.running'))

@bp.route('/running')
def running():
    # data request
    if request.args.has_key('j'):
        return json_get_running()
    # template request
    return render_template('running.html')

@bp.route('/active')
def active():
    # data request
    if request.args.has_key('j'):
        level = int(request.args.get('level', 0))
        if level == 0:
            level = None
        return json_get_loc_severity(level)
    # template request
    return render_template('active.html')

@bp.route('/hosts')
def ips():
    # data request
    if request.args.has_key('j'):
        return json_get_ip_locs()
    # template request
    return render_template('hosts.html')
