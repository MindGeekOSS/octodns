#
#
#

from __future__ import absolute_import, division, print_function, \
    unicode_literals

from os import makedirs
from os.path import isdir, join
import logging
import csv

from .base import BaseProvider


class CsvProvider(BaseProvider):
    '''
    Core provider for records configured in csv files on disk.

    config:
        class: octodns.provider.csv.CsvProvider
        # The location of yaml config files (required)
        directory: ./config
    '''
    SUPPORTS_GEO = True
    SUPPORTS = set(('A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'MX', 'NAPTR', 'NS',
                    'PTR', 'SSHFP', 'SPF', 'SRV', 'TXT'))

    def __init__(self, id, directory, *args, **kwargs):
        self.log = logging.getLogger('CsvProvider[{}]'.format(id))
        self.log.debug('__init__: id=%s, directory=%s', id, directory)
        super(CsvProvider, self).__init__(id, *args, **kwargs)
        self.directory = directory

    def populate(self, zone, target=False, lenient=False):
        self.log.debug('populate: name=%s, target=%s, lenient=%s', zone.name,
                       target, lenient)
        self.log.info('populate:   found %s records',
                      len(zone.records))

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug('_apply: zone=%s, len(changes)=%d', desired.name,
                       len(changes))

        csv_columns = ['zone',
                       'type',
                       'record',
                       'ttl',
                       'value',
                       'geo',
                       'healthcheck']

        # Since we don't have existing we'll only see creates
        records = [c.new for c in changes]
        dict_data = []
        for record in records:
            d = record.data
            if 'values' in d:
                d['value'] = d['values']
                del d['values']
            d['type'] = record._type
            record_key = "{}.{}".format(record.name, desired.name)
            d['record'] = record_key
            d['zone'] = desired.name
            dict_data.append(d)

        if not isdir(self.directory):
            makedirs(self.directory)

        filename = join(self.directory, '{}csv'.format(desired.name))
        self.log.debug('_apply:   writing filename=%s', filename)
        with open(filename, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for data in dict_data:
                writer.writerow(data)
