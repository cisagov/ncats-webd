#!/usr/bin/env python
'''Outputs CSV data for all CyHy stakeholders.

Usage:
  COMMAND_NAME [--section SECTION]
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.
'''

import sys
import os
import re
from docopt import docopt
import netaddr
import datetime
from cyhy.db import database
from cyhy.util import util
from bson import ObjectId
import csv
import StringIO

def get_first_snapshot_times(db, owners):
    first_snapshot_time_by_owner = list(db.SnapshotDoc.collection.aggregate([
            {'$match': {'owner': {'$in':owners}}},
            {'$project': {'owner':1, 'start_time':1}},
            {'$sort': {'owner':1, 'start_time':1}},
            {'$group': {'_id':'$owner',
                        'first_snapshot_start_time': {'$first':'$start_time'}}},
            {'$sort': {'_id':1}}
            ], cursor={}))

    first_snapshot_time_dict = dict()
    for i in first_snapshot_time_by_owner:
        first_snapshot_time_dict[i['_id']] = i['first_snapshot_start_time']
    return first_snapshot_time_dict

def write_stakeholders_csv(db):
    org_types = db.RequestDoc.get_owner_to_type_dict(stakeholders_only=True)
    stakeholder_ids = org_types.keys()
    first_snapshot_time_dict = get_first_snapshot_times(db, stakeholder_ids)

    all_CI_orgs = db.RequestDoc.get_all_descendants('CRITICAL_INFRASTRUCTURE')
    all_ELECTION_orgs = db.RequestDoc.get_all_descendants('ELECTION')

    CI_sectors = dict()
    for sector in db.RequestDoc.get_by_owner('CRITICAL_INFRASTRUCTURE')['children']:
        CI_sectors[sector] = db.RequestDoc.get_by_owner(sector)['children']

    csvrow = []
    new_csvfile = StringIO.StringIO()
    wr = csv.writer(new_csvfile)
    wr.writerow(('Organization ID','Organization Name','City','County','State','GNIS ID','Organization Type','Critical Infrastructure','CI Sector','Scheduler','Reporting Period','Election','First Scan'))
    stakeholders = db.RequestDoc.find({'_id':{'$in':stakeholder_ids}}).sort([('_id',1)])
    for org in stakeholders:
        org_ELECTION = 'No'
        if org['_id'] in all_ELECTION_orgs:
            org_ELECTION = 'Yes'

        first_scan = first_snapshot_time_dict.get(org['_id'], 'No Scans')

        org_CI = 'No'
        org_CI_sector = ''
        if org['_id'] in all_CI_orgs:
            org_CI = 'Yes'
            for sector in CI_sectors.keys():
                if org['_id'] in CI_sectors[sector]:
                    org_CI_sector = sector
                    break

        wr.writerow(('{}'.format(org['_id']),'{}'.format(org['agency']['name']),'{}'.format(org['agency']['location']['name'].encode('utf-8')),'{}'.format(org['agency']['location']['county']),'{}'.format(org['agency']['location']['state']),'{}'.format(org['agency']['location']['gnis_id']),'{}'.format(org_types[org['_id']]),'{}'.format(org_CI),'{}'.format(org_CI_sector),'{}'.format(org['scheduler']),'{}'.format(org['report_period']),'{}'.format(org_ELECTION),'{}'.format(first_scan)))

    return new_csvfile

def write_stakeholders(db):
    org_types = db.RequestDoc.get_owner_to_type_dict(stakeholders_only=True)
    stakeholder_ids = org_types.keys()
    first_snapshot_time_dict = get_first_snapshot_times(db, stakeholder_ids)

    all_CI_orgs = db.RequestDoc.get_all_descendants('CRITICAL_INFRASTRUCTURE')
    all_ELECTION_orgs = db.RequestDoc.get_all_descendants('ELECTION')

    CI_sectors = dict()
    for sector in db.RequestDoc.get_by_owner('CRITICAL_INFRASTRUCTURE')['children']:
        CI_sectors[sector] = db.RequestDoc.get_by_owner(sector)['children']

    stakeholder_list = []
    stakeholder_list.append(('Organization ID','Organization Name','City','County','State','GNIS ID','Organization Type','Critical Infrastructure','CI Sector','Scheduler','Reporting Period','Election','First Scan'))
    stakeholders = db.RequestDoc.find({'_id':{'$in':stakeholder_ids}}).sort([('_id',1)])
    for org in stakeholders:
        org_ELECTION = 'No'
        if org['_id'] in all_ELECTION_orgs:
            org_ELECTION = 'Yes'

        first_scan = first_snapshot_time_dict.get(org['_id'], 'No Scans')

        org_CI = 'No'
        org_CI_sector = 'N/A'
        if org['_id'] in all_CI_orgs:
            org_CI = 'Yes'
            for sector in CI_sectors.keys():
                if org['_id'] in CI_sectors[sector]:
                    org_CI_sector = sector
                    break

        stakeholder_list.append(('{}'.format(org['_id']),'{}'.format(org['agency']['name']),'{}'.format(org['agency']['location']['name'].encode('utf-8')),'{}'.format(org['agency']['location']['county']),'{}'.format(org['agency']['location']['state']),'{}'.format(org['agency']['location']['gnis_id']),'{}'.format(org_types[org['_id']]),'{}'.format(org_CI),'{}'.format(org_CI_sector),'{}'.format(org['scheduler']),'{}'.format(org['report_period']),'{}'.format(org_ELECTION),'{}'.format(first_scan)))

    return stakeholder_list

def main():
    global __doc__
    __doc__ = re.sub('COMMAND_NAME', __file__, __doc__)
    args = docopt(__doc__, version='v0.0.1')
    db = database.db_from_config(args['--section'])
    # print write_stakeholders_csv(db).getvalue()
    stakeholders = write_stakeholders(db)
    # for i in stakeholders:
    #     print i

if __name__=='__main__':
    main()
