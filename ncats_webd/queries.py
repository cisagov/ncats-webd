from cyhy.core import STAGE, STATUS
from cyhy.core.common import REPORT_TYPE

class MapQueries:

    @staticmethod
    def get_open_ticket_loc_by_severity(db, severity=None):
        if severity != None:
            tickets = db.TicketDoc.collection.find({'open':True, 'details.severity':severity, 'loc.0':{'$ne':None}},
                                                   {'_id':0,'loc':1,'details.severity':1})
        else:
            tickets = db.TicketDoc.collection.find({'open':True, 'loc.0':{'$ne':None}},{'_id':0,'loc':1,'details.severity':1})
        return list(tickets)

    @staticmethod
    def get_running_ips(db):
        running_ips = db.HostDoc.collection.find({'status':'RUNNING'}, {'_id':0, 'loc':1, 'stage':1})
        return list(running_ips)

    @staticmethod
    def get_host_locations(db):
        host_locations = db.HostDoc.collection.find({'state.up':True}, {'_id':0, 'loc':1})
        return list(host_locations)

class HiringDashboardQueries:

    @staticmethod
    def get_current_billets(db):
        # Fix this issue to work with HireDoc Collection and not new_hire
        # billets = db.HireDoc.collection.find({'active': True},{'position_number':1, "insert_date":1, 'date_stage_entered':1, 'current_stage':1, 'eod':1, 'billet_started':1}).sort([("billet_started", 1), ("stage.current", -1)])
        billets = db.new_hire.find({'active': True},{'position_number':1, "insert_date":1, 'date_stage_entered':1, 'current_stage':1, 'eod':1, 'billet_started':1, 'sub_component':1}).sort([("billet_started", 1), ("stage.current", -1)])
        return list(billets)


class DashboardQueries:

    @staticmethod
    def build_stakeholder_list(db):
        stakeholders = []
        for r in db.requests.find({'stakeholder':True}):
            stakeholders.append(r['_id'])
        return stakeholders

    @staticmethod
    def get_ticket_severity_counts(db, stakeholders):
        results = dict()
        results['ticket_data'] = dict()
        for org in stakeholders: #db.requests.find({'stakeholder':True}):
            if org.get('children'):
                current_org_list = [org['_id']] + db.RequestDoc.get_all_descendants(org['_id'])
            else:
                current_org_list = [org['_id']]
            tix = list(db.tickets.aggregate([
                {'$match':{'open':True, 'owner':{'$in':current_org_list}, 'false_positive':False}},
                {'$group': {'_id': {},
                            'critical_tix_open':{'$sum':{'$cond':[{'$eq':['$details.severity',4]}, 1, 0]}},
                            'high_tix_open':{'$sum':{'$cond':[{'$eq':['$details.severity',3]}, 1, 0]}}
                           }}], cursor={}))

            if len(tix) > 0:
                results['ticket_data'][org['_id']] = {'org_name':org['agency']['name'],
                                                      'critical_open':tix[0].get('critical_tix_open', 0),
                                                      'high_open':tix[0].get('high_tix_open', 0)}
            else:
                results['ticket_data'][org['_id']] = {'org_name':org['agency']['name'],
                                                      'critical_open':0,
                                                      'high_open':0}

        # Reverse sort on critical_open, then high_open, then normal (alphabetical) sort on org_name
        sorted_ticket_data = sorted(results['ticket_data'].values(),
            key=lambda(v):(-v['critical_open'], -v['high_open'], v['org_name']))
        return sorted_ticket_data


    @staticmethod
    def get_overall_metrics(db, stakeholders):
        results = dict()
        results['stakeholders'] = len(stakeholders)
        results['addresses'] = db.hosts.count()
        results['hosts'] = db.hosts.find({'state.up':True}).count()
        results['vulnerable_hosts'] = len(db.tickets.find({'open':True, 'false_positive':False}).distinct('ip_int'))

        tix = list(db.tickets.aggregate([
            {'$match':{'open':True, 'false_positive':False}},
            {'$group': {'_id': {},
                 'low_tix_open':{'$sum':{'$cond':[{'$eq':['$details.severity',1]}, 1, 0]}},
                 'medium_tix_open':{'$sum':{'$cond':[{'$eq':['$details.severity',2]}, 1, 0]}},
                 'high_tix_open':{'$sum':{'$cond':[{'$eq':['$details.severity',3]}, 1, 0]}},
                 'critical_tix_open':{'$sum':{'$cond':[{'$eq':['$details.severity',4]}, 1, 0]}},
                 'total_tix_open':{'$sum':1}
             }}], cursor={}))



        results['open_tickets'] = {'low':tix[0]['low_tix_open'],
                                   'medium':tix[0]['medium_tix_open'],
                                   'high':tix[0]['high_tix_open'],
                                   'critical':tix[0]['critical_tix_open'],
                                   'total':tix[0]['total_tix_open']}

        results['reports'] = db.reports.find({'report_types':REPORT_TYPE.CYHY}).count()
        return results

    @staticmethod
    def get_tally_details(db):
        results = dict()
        stage_status_counts = list(db.tallies.aggregate([
            {
                '$group': {
                    '_id':'null',
                    'ns1_waiting':{'$sum':'$counts.NETSCAN1.WAITING'},
                    'ns1_ready':{'$sum':'$counts.NETSCAN1.READY'},
                    'ns1_running':{'$sum':'$counts.NETSCAN1.RUNNING'},
                    'ns2_waiting':{'$sum':'$counts.NETSCAN2.WAITING'},
                    'ns2_ready':{'$sum':'$counts.NETSCAN2.READY'},
                    'ns2_running':{'$sum':'$counts.NETSCAN2.RUNNING'},
                    'ps_waiting':{'$sum':'$counts.PORTSCAN.WAITING'},
                    'ps_ready':{'$sum':'$counts.PORTSCAN.READY'},
                    'ps_running':{'$sum':'$counts.PORTSCAN.RUNNING'},
                    'vs_waiting':{'$sum':'$counts.VULNSCAN.WAITING'},
                    'vs_ready':{'$sum':'$counts.VULNSCAN.READY'},
                    'vs_running':{'$sum':'$counts.VULNSCAN.RUNNING'}
                }
            },
            {
                '$project': {
                    'ns1_waiting':{'$add':['$ns1_waiting', '$ns1_ready']},
                    'ns1_running':1,
                    'ns2_waiting':{'$add':['$ns2_waiting', '$ns2_ready']},
                    'ns2_running':1,
                    'ps_waiting':{'$add':['$ps_waiting', '$ps_ready']},
                    'ps_running':1,
                    'vs_waiting':{'$add':['$vs_waiting', '$vs_ready']},
                    'vs_running':1
                }
            }
        ], cursor={}))

        for queue_name in ['ns1_waiting','ns1_running','ns2_waiting','ns2_running','ps_waiting','ps_running','vs_waiting','vs_running']:
            results[queue_name] = stage_status_counts[0][queue_name]

        return results

    @staticmethod
    def build_election_list(db):
        all_stakeholders = []
        for r in db.requests.find({'stakeholder': True}):
            all_stakeholders.append(r['_id'])

        election_orgs = db.RequestDoc.get_all_descendants('ELECTION')
        # NOTE: Includes all orgs, not just stakeholders

        election_stakeholders = list(set(all_stakeholders) & set(election_orgs))

        return election_stakeholders

    @staticmethod
    def get_election_metrics(db):
        results = dict()
        all_stakeholders = []
        for r in db.requests.find({'stakeholder': True}):
            all_stakeholders.append(r['_id'])

        election_orgs = db.RequestDoc.get_all_descendants('ELECTION')
        # NOTE: Includes all orgs, not just stakeholders

        election_stakeholders = list(set(all_stakeholders) & set(election_orgs))

        results['stakeholders'] = len(election_stakeholders)
        results['addresses'] = db.hosts.find({'owner': {'$in': election_orgs}}).count()
        results['hosts'] = db.hosts.find({'state.up': True, 'owner': {'$in': election_orgs}}).count()
        results['vulnerable_hosts'] = len(db.tickets.find({'open': True, 'owner': {'$in': election_orgs}, 'false_positive': False}).distinct(
            'ip_int'))

        tix = list(db.tickets.aggregate([
            {'$match': {'open': True, 'owner': {'$in': election_orgs}, 'false_positive': False}},
            {'$group': {'_id': {},
                        'low_tix_open': {'$sum': {'$cond': [{'$eq': ['$details.severity', 1]}, 1, 0]}},
                        'medium_tix_open': {'$sum': {'$cond': [{'$eq': ['$details.severity', 2]}, 1, 0]}},
                        'high_tix_open': {'$sum': {'$cond': [{'$eq': ['$details.severity', 3]}, 1, 0]}},
                        'critical_tix_open': {'$sum': {'$cond': [{'$eq': ['$details.severity', 4]}, 1, 0]}},
                        'total_tix_open': {'$sum': 1}
                        }}], cursor={}))

        results['open_tickets'] = {'low':tix[0]['low_tix_open'],
                                   'medium':tix[0]['medium_tix_open'],
                                   'high':tix[0]['high_tix_open'],
                                   'critical':tix[0]['critical_tix_open'],
                                   'total':tix[0]['total_tix_open']}

        results['reports'] = db.reports.find({'owner': {'$in': election_orgs}}).count()
        return results
