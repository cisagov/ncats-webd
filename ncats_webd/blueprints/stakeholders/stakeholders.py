import sys
import json

from flask import Blueprint, render_template, current_app, flash, redirect, url_for, request, Response
from cyhy.util import util
from ncats_webd.common import cache
from dateutil import parser

import contacts
import stakeholders_info

BLUEPRINT_NAME = 'stakeholders'
bp = Blueprint(BLUEPRINT_NAME, __name__,
               template_folder='templates',
               static_folder='static')

#import IPython; IPython.embed() #<<< BREAKPOINT >>>

###############################################################################
#  Data Access
###############################################################################

@cache.memoize(timeout=300)
def csv_contacts():
    csvfile = contacts.write_contacts_csv(current_app.db)
    
    response = Response(csvfile.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=contacts.csv'
    return response
    
@cache.memoize(timeout=300)
def csv_stakeholders():
    csvfile = stakeholders_info.write_stakeholders_csv(current_app.db)
    
    response = Response(csvfile.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=stakeholders.csv'
    return response
    
@cache.memoize(timeout=300)
def general_stats():
    return stakeholders_info.write_stakeholders(current_app.db)
    
@bp.route('/')
def main_route():
    data = general_stats()
    return json.dumps(data, default=util.custom_json_handler)

@bp.route('/contacts')
def contacts_route():
    return csv_contacts()
    
@bp.route('/stakeholders')
def stakeholders_route():
    return csv_stakeholders()


