#
#
#

from __future__ import absolute_import, division, print_function, \
    unicode_literals

import threading
from logging import getLogger
from collections import OrderedDict, defaultdict
from functools import wraps
from ns1 import NS1
from ns1.rest.errors import RateLimitException, ResourceException
from incf.countryutils.transformations import cc_to_cn, cn_to_ctca2
from time import sleep

from ..record import Record
from .base import BaseProvider


def ratelimited(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        while True:
            if self._ratelimited:
                sleep(1)
                continue
            try:
                return method(self, *args, **kwargs)
            except RateLimitException as e:
                if self._ratelimited:
                    continue
                with self._lock:
                    self._ratelimited = True
                    self.log.debug('%s: rate limit exceeded, throttling',
                                  method.__name__)
                    sleep(int(e.period) / 10)
                    self._ratelimited = False
    return wrapper


class Ns1Provider(BaseProvider):
    '''
    Ns1 provider

    ns1:
        class: octodns.provider.ns1.Ns1Provider
        api_key: env/NS1_API_KEY
    '''
    SUPPORTS_GEO = True
    SUPPORTS = set(('A', 'AAAA', 'ALIAS', 'CAA', 'CNAME', 'MX', 'NAPTR',
                    'NS', 'PTR', 'SPF', 'SRV', 'TXT'))
    ZONE_NOT_FOUND_MESSAGE = 'server error: zone not found'
    GEO_FILTER_CHAIN = [
        {"filter": "shuffle", "config": {}},
        {"filter": "geotarget_country", "config": {}},
        {"filter": "select_first_n", "config": {"N": 1}}
    ]
    _instance = None
    _lock = threading.Lock()
    _ratelimited = False

    def __new__(cls, *args, **kwargs):
        if Ns1Provider._instance is None:
            with Ns1Provider._lock:
                if Ns1Provider._instance is None:
                    Ns1Provider._instance = (
                        super(Ns1Provider, cls).__new__(cls, *args, **kwargs)
                    )
        return Ns1Provider._instance

    def __init__(self, id, api_key, nameservers=[], *args, **kwargs):
        self.log = getLogger('Ns1Provider[{}]'.format(id))
        self.log.debug('__init__: id=%s, api_key=***', id)
        self.nameservers = nameservers
        super(Ns1Provider, self).__init__(id, *args, **kwargs)
        _NS1 = NS1(apiKey=api_key)
        self._NS1Records = _NS1.records()
        self._NS1Zones = _NS1.zones()
        self._zone_cache = {}
        self._record_cache = {}

    def _reset_cache(self):
        self._zone_cache = {}
        self._record_cache = {}

    @ratelimited
    def _loadZone(self, zone, create=False):
        zone = zone.rstrip('.')
        if zone not in self._zone_cache:
            if create:
                self.log.debug('_loadZone: creating zone %s', zone)
                self._zone_cache[zone] = self._NS1Zones.create(zone)
            else:
                try:
                    self.log.debug('_loadZone: loading zone %s', zone)
                    self._zone_cache[zone] = self._NS1Zones.retrieve(zone)
                except ResourceException as e:
                    if e.message != self.ZONE_NOT_FOUND_MESSAGE:
                        raise
        self.log.debug('_loadZone: loading zone %s from cache', zone)
        return self._zone_cache.get(zone)

    @ratelimited
    def _loadRecord(self, domain, _type, zone):
        domain = domain.rstrip('.')
        zone = zone.rstrip('.')
        rec = (zone, domain, _type)
        if rec not in self._record_cache:
            self.log.debug('_loadRecord: loading record %s/%s/%s', *rec)
            self._record_cache[rec] = self._NS1Records.retrieve(*rec)
        self.log.debug('_loadRecord: loading record %s/%s/%s from cache', *rec)
        return self._record_cache.get(rec)

    def _data_for_A(self, _type, record):
        data = {'ttl': record['ttl'], 'type': _type, 'values': [],
                'geo': defaultdict(list)}

        # If it's not a geo-enabled record, we'll only have the short version
        # returned by the /v1/zones/<zone> endpoint, which has no metadata.
        if record['tier'] == 1:
            data['values'] = record.get('answers', [])
            return data

        # For geo-enabled records we will have the full record object.
        for answer in record.get('answers', []):
            note = answer.get('meta', {}).get('note')
            if note and note.startswith('octodns_region_code:'):
                region = note.split(':')[1]
                data['geo'][region].extend(answer['answer'])
            else:
                # No geo metadata means this is the regionless default answer
                # that octo requires be present on all geo records.
                data['values'].extend(answer['answer'])

        return data

    _data_for_AAAA = _data_for_A

    def _data_for_SPF(self, _type, record):
        # NS1 doesn't escape semicolons in SPF rdata, so escape them here.
        values = [v.replace(';', '\\;') for v in record['answers']]
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': values
        }

    _data_for_TXT = _data_for_SPF

    def _data_for_CAA(self, _type, record):
        values = []
        for answer in record['answers']:
            flags, tag, value = answer.split(' ', 2)
            values.append({
                'flags': flags,
                'tag': tag,
                'value': value,
            })
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': values,
        }

    def _data_for_CNAME(self, _type, record):
        try:
            value = self._fqdn(record['answers'][0])
        except IndexError:
            value = None
        return {
            'ttl': record['ttl'],
            'type': _type,
            'value': value,
        }

    _data_for_ALIAS = _data_for_CNAME
    _data_for_PTR = _data_for_CNAME

    def _data_for_MX(self, _type, record):
        values = []
        for answer in record['answers']:
            preference, exchange = answer.split(' ', 1)
            values.append({
                'preference': preference,
                'exchange': self._fqdn(exchange),
            })
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': values,
        }

    def _data_for_NAPTR(self, _type, record):
        values = []
        for answer in record['answers']:
            order, preference, flags, service, regexp, replacement = \
                answer.split(' ', 5)
            values.append({
                'flags': flags,
                'order': order,
                'preference': preference,
                'regexp': regexp,
                'replacement': replacement,
                'service': service,
            })
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': values,
        }

    def _data_for_NS(self, _type, record):
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': [self._fqdn(a) for a in record['answers']],
        }

    def _data_for_SRV(self, _type, record):
        values = []
        for answer in record['answers']:
            priority, weight, port, target = answer.split(' ', 3)
            values.append({
                'priority': priority,
                'weight': weight,
                'port': port,
                'target': self._fqdn(target),
            })
        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': values,
        }

    def _data_for(self, _type, record):
        data_for_type = getattr(self, '_data_for_%s' % _type)
        return data_for_type(_type, record)

    def _fqdn(self, name):
        return "%s." % name.rstrip('.')

    def populate(self, zone, target=False, lenient=False):
        self.log.debug('populate: name=%s, target=%s, lenient=%s',
                       zone.name, target, lenient)

        ns1_zone = self._loadZone(zone.name)
        if not ns1_zone:
            self.log.info('populate:   found 0 records, exists=False')
            return False

        count = 0
        for record in ns1_zone.get('records', []):
            _type = record['type']
            if _type not in self.SUPPORTS:
                continue
            count += 1
            record['answers'] = record['short_answers']
            if record['tier'] != 1:
                record = self._loadRecord(record['domain'], _type, zone.name)
            name = zone.hostname_from_fqdn(record['domain'])
            record = Record.new(zone, name, self._data_for(_type, record),
                                source=self, lenient=lenient)
            zone.add_record(record, lenient=lenient)

        self.log.info('populate:   found %s records, exists=True', count)
        return True

    def _params_for_A(self, record):
        params = {
            'answers': filter(lambda x: x not in self.nameservers,
                              record.values),
            'ttl': record.ttl
        }
        geo = False

        for iso_region_code, target in getattr(record, 'geo', {}).items():
            meta = {'note': 'octodns_region_code:%s' % iso_region_code}
            parts = iso_region_code.split('-')
            country = parts[1] if len(parts) > 1 else None
            state = parts[2] if len(parts) > 2 else None
            if country:
                geo = True
                if state and country == 'US':
                    meta['us_state'] = state
                elif state and country == 'CA':
                    meta['ca_province'] = state
                else:
                    meta['country'] = country
            for ans in target.values:
                params['answers'].append({'answer': [ans], 'meta': meta})

        params['filters'] = self.GEO_FILTER_CHAIN if geo else []
        return params

    _params_for_AAAA = _params_for_A
    _params_for_NS = _params_for_A

    def _params_for_SPF(self, record):
        # NS1 doesn't escape semicolons in SPF rdata, so unescape them here.
        values = [v.replace('\\;', ';') for v in record.values]
        return {'answers': values, 'ttl': record.ttl}

    _params_for_TXT = _params_for_SPF

    def _params_for_CAA(self, record):
        values = [(v.flags, v.tag, v.value) for v in record.values]
        return {'answers': values, 'ttl': record.ttl}

    def _params_for_CNAME(self, record):
        return {'answers': [record.value], 'ttl': record.ttl}

    _params_for_ALIAS = _params_for_CNAME
    _params_for_PTR = _params_for_CNAME

    def _params_for_MX(self, record):
        values = [(v.preference, v.exchange) for v in record.values]
        return {'answers': values, 'ttl': record.ttl}

    def _params_for_NAPTR(self, record):
        values = [(v.order, v.preference, v.flags, v.service, v.regexp,
                   v.replacement) for v in record.values]
        return {'answers': values, 'ttl': record.ttl}

    def _params_for_SRV(self, record):
        values = [(v.priority, v.weight, v.port, v.target)
                  for v in record.values]
        return {'answers': values, 'ttl': record.ttl}

    def _params_for(self, record):
        params_for_type = getattr(self, '_params_for_%s' % record._type)
        return params_for_type(record)

    @ratelimited
    def _apply_Create(self, change):
        rec = change.new
        zone = rec.zone.name.rstrip('.')
        domain = rec.fqdn.rstrip('.')
        params = self._params_for(rec)
        self.log.debug('_apply_Create: creating record %s/%s/%s: %s',
                       zone, domain, rec._type, params)
        self._NS1Records.create(zone, domain, rec._type, **params)

    @ratelimited
    def _apply_Update(self, change):
        rec = change.new
        zone = rec.zone.name.rstrip('.')
        domain = rec.fqdn.rstrip('.')
        params = self._params_for(rec)
        self.log.debug('_apply_Create: updating record %s/%s/%s: %s',
                       zone, domain, rec._type, params)
        self._NS1Records.update(zone, domain, rec._type, **params)

    @ratelimited
    def _apply_Delete(self, change):
        rec = change.existing
        zone = rec.zone.name.rstrip('.')
        domain = rec.fqdn.rstrip('.')
        self.log.debug('_apply_Delete: deleting record %s/%s/%s)',
                       zone, domain, rec._type)
        self._NS1Records.delete(zone, domain, rec._type)

    def _apply(self, plan):
        self.log.debug('_apply: applying %d change(s) for zone %s',
                       len(plan.changes), plan.desired.name)
        self._loadZone(plan.desired.name, create=True)
        for change in plan.changes:
            make = getattr(self, '_apply_%s' % change.__class__.__name__)
            make(change)
