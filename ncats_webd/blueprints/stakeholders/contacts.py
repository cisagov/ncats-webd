#!/usr/bin/env python
'''Macro Contacts one-off application.

Usage:
  macro_contacts.py [--section SECTION]
  macro_contacts.py (-h | --help)
  macro_contacts.py --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.
'''

from docopt import docopt
from cyhy.db import database
import csv
import sys
import StringIO
            
def write_contacts_csv(db):
    data = db.RequestDoc.find().sort('_id',1)
    contact_buffer = []
    has_distro = False
    output = StringIO.StringIO()
    for doc in data:
        # if contacts is not empty, iterate through and print
        if doc['agency']['contacts']:
            if contact_buffer and has_distro == False:
                for i in contact_buffer:
                    output.write(i[0] + ',' + i[1] + ',')
            output.write('\n')
            contact_buffer = []
            has_distro = False
            output.write(doc['_id'] + ',')
            try:
                # prevent commas in name. Get rid of spaces
                output.write('"' + doc['agency']['name'] + '"' + ',' + doc['agency']['type'] + ',',)
            except:
                output.write(''),
            for counter in enumerate(doc['agency']['contacts']):
                # search for distro and print if exists
                try:
                    if counter[1]['type'] == 'DISTRO':
                        output.write(counter[1]['name'] + ',' + counter[1]['email'] + ',')
                        has_distro = True
                        break
                except:
                    output.write('',)
                # if not, print all technicals
                contact_buffer.append((counter[1]['name'], counter[1]['email']))
                    
    if contact_buffer and has_distro == False:
        for i in contact_buffer:
            output.write(i[0] + ',' + i[1] + ',')
            
    return output
            
def main():
    args = docopt(__doc__, version='v0.0.1')
    db = database.db_from_config(args['--section'])
    #import IPython; IPython.embed() #<<< BREAKPOINT >>>
    print write_contacts_csv(db).getvalue()
    
if __name__=='__main__':
    main()
