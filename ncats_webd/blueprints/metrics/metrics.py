import sys
import json

from flask import Blueprint, render_template, current_app, flash, redirect, url_for, request, Response
from cyhy.util import util
from ncats_webd.common import cache
from dateutil import parser

import FYcalcs
import ticketReport
import risk_me
import fema_stats
import congressional_metrics

BLUEPRINT_NAME = 'metrics'
bp = Blueprint(BLUEPRINT_NAME, __name__,
               template_folder='templates',
               static_folder='static')

###############################################################################
#  Data Access
###############################################################################

# cache these 3 expensive functions for an hour - taking into account the args
@cache.memoize(timeout=3600)
def top_OS(FY_START, FY_END, db):
    return FYcalcs.top_OS(FY_START, FY_END, db)

@cache.memoize(timeout=3600)
def num_addresses_hosts_scanned(FY_START, FY_END, db):
    return FYcalcs.num_addresses_hosts_scanned(FY_START, FY_END, db)

@cache.memoize(timeout=3600)
def top_services(FY_START, FY_END, db):
    return FYcalcs.top_services(FY_START, FY_END, db)

@cache.memoize(timeout=300)
def weekly_tickets_data():
    rd, stats = ticketReport.get_stats(current_app.db)
    return stats

@cache.memoize(timeout=300)
def risk_rating_data():
    return risk_me.get_ranking_lists(current_app.db)

@cache.memoize(timeout=300)
def fema_data():
    return fema_stats.fema_detail(current_app.db)

@cache.memoize(timeout=300)
def fema_download():
    csvfile = fema_stats.fema_csv(current_app.db)
    response = Response(csvfile.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=fema.csv'
    return response

#@cache.memoize(timeout=300)
#def contacts():
#    return contacts.write_contacts_csv(current_app.db)
#
#@cache.memoize(timeout=300)
#def stakeholders():
#    return stakeholders.write_stakeholders_csv(current_app.db)

@cache.memoize(timeout=300)
def congressional_metrics_pull(db,start_date,end_date):
    return congressional_metrics.congressional_data(db,start_date,end_date)

###############################################################################
#  Routes
###############################################################################

@bp.route('/weekly')
def weekly_tickets():
    data = weekly_tickets_data()

    # data request
    if request.args.has_key('j'):
        return json.dumps(data, default=util.custom_json_handler)

    return render_template('weekly_tickets.html',TICKET=data)

@bp.route('/risk')
def risk_rating():
    data = risk_rating_data()
    return json.dumps(data, default=util.custom_json_handler)

@bp.route('/fema')
def fema_numbers():
    data = fema_data()
    return json.dumps(data, default=util.custom_json_handler)

@bp.route('/fema_csv')
def fema_route():
    return fema_download()

@bp.route('/congressional', methods=['POST'])
def congressional_data():
    # format the dates
    ds = request.form.get('start')
    de = request.form.get('end')
    try:
        FY_START = parser.parse(ds)
        FY_END = parser.parse(de)
    except (ValueError, TypeError, AttributeError), e:
        flash('Unsuccessful query. Check date format\n')
        return redirect(url_for(BLUEPRINT_NAME+'.root'))

    data = congressional_metrics_pull(current_app.db,FY_START,FY_END)
    #data = congressional_metrics_pull(current_app.db,"20170101","20170901")
    return json.dumps(data, default=util.custom_json_handler)

@bp.route('/', endpoint='root')
def metrics_query():
    return render_template('query.html')

@bp.route('/results', methods=['GET','POST'])
def query_results():
    # format the dates
    ds = request.form.get('start')
    de = request.form.get('end')
    try:
        FY_START = parser.parse(ds)
        FY_END = parser.parse(de)
    except (ValueError, TypeError, AttributeError), e:
        # data request
        if request.args.has_key('j'):
            return json.dumps({"success": False, "flash": "Unsuccessful query. Check date format\n"}, default=util.custom_json_handler)
        else:
            flash('Unsuccessful query. Check date format\n')
            return redirect(url_for(BLUEPRINT_NAME+'.root'))

    # all vars are none
    vuln_t_c = top_vul = topOS = topVulnServ = topServ = numOrgs = numAddrHostsScanned = numReports = avg_cvss = uVulns = nVulnDet = None
    # grab current FED SLTT PRIVATE from other main
    FYcalcs.categorize_orgs(current_app.db)

    # call for relevant info
    if request.form.get('vuln_ticket_count'):
        vuln_t_c = FYcalcs.vuln_ticket_counts(FY_START, FY_END, current_app.db, int(request.form.get('vuln_ticket_count')))

    if request.form.get('top_vulns'):
        top_vul = FYcalcs.top_vulns(FY_START, FY_END, current_app.db, int(request.form.get('top_vulns')))

    if request.form.get('top_OS'):
        #topOS = FYcalcs.top_OS(FY_START, FY_END, current_app.db)
        topOS = top_OS(FY_START, FY_END, current_app.db)

    if request.form.get('top_vuln_services'):
        topVulnServ = FYcalcs.top_vuln_services(FY_START, FY_END, current_app.db)

    if request.form.get('top_services'):
        #topServ = FYcalcs.top_services(FY_START, FY_END, current_app.db)
        topServ = top_services(FY_START, FY_END, current_app.db)

    if request.form.get('num_orgs_scanned'):
        numOrgs = FYcalcs.num_orgs_scanned(FY_START, FY_END, current_app.db)

    if request.form.get('num_addresses_hosts_scanned'):
        #numAddrHostsScanned = FYcalcs.num_addresses_hosts_scanned(FY_START, FY_END, current_app.db)
        numAddrHostsScanned = num_addresses_hosts_scanned(FY_START, FY_END, current_app.db)

    if request.form.get('num_reports_generated'):
        numReports = FYcalcs.num_reports_generated(FY_START, FY_END, current_app.db)

    if request.form.get('avg_cvss_score'):
        avg_cvss = FYcalcs.avg_cvss_score(FY_START, FY_END, current_app.db)

    if request.form.get('unique_vulns'):
        uVulns = FYcalcs.unique_vulns(FY_START, FY_END, current_app.db)

    if request.form.get('new_vuln_detections'):
        nVulnDet = FYcalcs.new_vuln_detections(FY_START, FY_END, current_app.db)

    if request.args.has_key('j'):
        return json.dumps({"success": True, "results": {"START":FY_START, "END":FY_END, "VULN_TICKET":vuln_t_c,"TOP_VULNS":top_vul,"TOP_OS":topOS,"TOPVULNSERV":topVulnServ,"TOPSERV":topServ,"NUMORGS":numOrgs,"NUMADDRHOSTS":numAddrHostsScanned,"NUMREPORTS":numReports,"AVGCVSS":avg_cvss,"UVULNS":uVulns,"NVULNDET":nVulnDet}}, default=util.custom_json_handler)
    else:
        return render_template('results.html', START=FY_START, END=FY_END, VULN_TICKET=vuln_t_c,TOP_VULNS=top_vul,TOP_OS=topOS,TOPVULNSERV=topVulnServ,TOPSERV=topServ,NUMORGS=numOrgs,NUMADDRHOSTS=numAddrHostsScanned,NUMREPORTS=numReports,AVGCVSS=avg_cvss,UVULNS=uVulns,NVULNDET=nVulnDet)
