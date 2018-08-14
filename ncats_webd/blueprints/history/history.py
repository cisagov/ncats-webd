import json
from flask import Blueprint, render_template, abort, current_app, request

from cyhy.util import util

BLUEPRINT_NAME = 'history'
bp = Blueprint(BLUEPRINT_NAME, __name__,
               template_folder='templates',
               static_folder='static')

###############################################################################
#  Data Access
###############################################################################

def json_get_latest_snapshots():
    return current_app.db.SnapshotDoc.collection.find({'latest':True},
        {'_id':False, 'owner':True, 'start_time':True,'end_time':True}) \
        .sort([('end_time',1)])

###############################################################################
#  Routes
###############################################################################

@bp.route('/')
def snapshots():
    # data request
    if request.args.has_key('j'):
        snapshots = [s for s in json_get_latest_snapshots()]
        return json.dumps(snapshots, default=util.custom_json_handler)
    return render_template('history.html')
