#!/usr/bin/env python
'''Export a CSV containing all points of contact

Usage:
  contacts.py [--section SECTION]
  contacts.py (-h | --help)
  contacts.py --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.
'''

import StringIO

from docopt import docopt

from cyhy.db import database

def write_contacts_csv(db):
    all_request_docs = db.RequestDoc.find().sort('_id',1)
    output = StringIO.StringIO()
    output.write('Org ID,Org Name,Org Type,Org Retired,Contact Name,Contact Email,Contact Type\n')
    for doc in all_request_docs:
        for contact in doc['agency'].get('contacts', []):
            output.write('{},"{}",{},{},"{}",{},{}\n'.format(
                doc['_id'],
                doc['agency']['name'],
                doc['agency'].get('type', 'N/A'),
                doc.get('retired', False),
                contact.get('name', 'N/A'),
                contact.get('email', 'N/A'),
                contact.get('type', 'N/A')
            ))

    return output

def main():
    args = docopt(__doc__, version='v0.0.1')
    db = database.db_from_config(args['--section'])
    #import IPython; IPython.embed() #<<< BREAKPOINT >>>
    print write_contacts_csv(db).getvalue()

if __name__=='__main__':
    main()
