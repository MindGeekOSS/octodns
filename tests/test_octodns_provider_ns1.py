#
#
#

from __future__ import absolute_import, division, print_function, \
    unicode_literals

from copy import deepcopy
import json
from mock import MagicMock
from ns1.rest.errors import AuthException, RateLimitException, \
    ResourceException
from os.path import dirname, join
from requests_mock import ANY, mock as requests_mock
from unittest import TestCase

from octodns.record import Record
from octodns.provider.ns1 import Ns1Provider, ratelimited
from octodns.provider.yaml import YamlProvider
from octodns.zone import Zone


def remove_octodns_record(octodns_zone, domain, _type):
    '''Remove a record by domain/type from an octodns.zone.Zone object.'''

    if domain.endswith(octodns_zone.name):
        domain = domain[:-len(octodns_zone.name)]
    for record in list(octodns_zone.records):
        if record.name == domain and record._type == _type:
            octodns_zone._remove_record(record)
            return record
    return None


def octodns_test_zone():
    '''Load the unit.tests zone config into an octodns.zone.Zone object.'''

    zone = Zone('unit.tests.', [])
    source = YamlProvider('test', join(dirname(__file__), 'config'))
    source.populate(zone)
    # Replace the unit test fixture's NS record with one of ours.
    remove_octodns_record(zone, '', 'NS')
    zone.add_record(Record.new(zone, '', {
        'ttl': 3600,
        'type': 'NS',
        'values': [
            'dns1.p01.nsone.net.',
            'dns2.p01.nsone.net.',
            'dns3.p01.nsone.net.',
            'dns4.p01.nsone.net.'
        ]
    }))
    return zone


def endpoint(path):
    '''Return an API endpoint URL given a relative endpoint path.'''
    return 'https://api.nsone.net/v1/%s' % path.lstrip('/')


class TestNs1Provider(TestCase):
    def setUp(self):
        with open(join(dirname(__file__), 'fixtures/ns1-zone.json')) as f:
            self.ns1_zone = json.load(f)
        with open(join(dirname(__file__), 'fixtures/ns1-geo-record.json')) as f:
            self.ns1_geo_record = json.load(f)

    def test_populate(self):
        provider = Ns1Provider('test', 'api-key')
        unit_test_zone = octodns_test_zone()

        # General errors (bad request, forbidden, not found, internal, timeout)
        for code in [400, 403, 404, 500, 504]:
            with requests_mock() as mock:
                mock.get(ANY, status_code=code)
                with self.assertRaises(ResourceException):
                    provider.populate(Zone('unit.tests.', []))

        # Auth error
        with requests_mock() as mock:
            mock.get(ANY, status_code=401)
            with self.assertRaises(AuthException):
                provider.populate(Zone('unit.tests.', []))

        # Zone not found, exception handled internally
        with requests_mock() as mock:
            mock.get(endpoint('/zones/unit.tests'), status_code=404,
                     json={"message": "zone not found"})
            provider.populate(Zone('unit.tests.', []))

        # Ratelimit error
        with requests_mock() as mock:
            # First return a 429 (rate limit error) and then a 200 to check that
            # RateLimitExceptions are handled internally
            mock.get(ANY, [{'status_code': 429, 'json': {}},
                           {'status_code': 200, 'json': {}}])
            provider.populate(Zone('unit.tests.', []))
            provider._reset_cache()

        # Existing NS1 zone with no records
        with requests_mock() as mock:
            mock.get(endpoint('/zones/unit.tests'), json={
                'zone': 'unit.tests',
                'records': [],
            })
            zone = Zone('unit.tests.', [])
            self.assertTrue(provider.populate(zone))
            self.assertEquals(set(), zone.records)
            provider._reset_cache()

        # Test skipping unsupported record types
        with requests_mock() as mock:
            mock.get(endpoint('/zones/unit.tests'), json={
                'zone': 'unit.tests',
                'records': [
                    {'domain': 'unsupported.unit.tests',
                     'type': 'UNSUPPORTED',
                     'ttl': 30,
                     'short_answers': ['1.1.1.1'],
                     'tier': 1,
                    },
                ],
            })
            zone = Zone('unit.tests.', [])
            self.assertTrue(provider.populate(zone))
            self.assertEquals(set(), zone.records)
            provider._reset_cache()

        # Test populating full unit.tests zone
        with requests_mock() as mock:
            mock.get(endpoint('/zones/unit.tests'), json=self.ns1_zone)
            mock.get(endpoint('/zones/unit.tests/unit.tests/A'),
                     json=self.ns1_geo_record)
            zone = Zone('unit.tests.', [])
            self.assertTrue(provider.populate(zone))
            self.assertEquals(15, len(zone.records))
            self.assertEquals(0, len(unit_test_zone.changes(zone, provider)))
            # Note: intentionally don't reset cache here

        # Test that repopulating the same zone just pulls from cache and makes
        # no actual calls.
        with requests_mock() as mock:
            mock.get(ANY, status_code=500)
            zone = Zone('unit.tests.', [])
            self.assertTrue(provider.populate(zone))
            self.assertEquals(15, len(zone.records))
            self.assertEquals(0, len(unit_test_zone.changes(zone, provider)))
            provider._reset_cache()

    def test_apply(self):
        provider = Ns1Provider('test', 'api-key')
        unit_test_zone = octodns_test_zone()

        zones_mock = MagicMock(return_value=None)
        zones_mock.retrieve.return_value = self.ns1_zone
        provider._NS1Zones = zones_mock

        records_mock = MagicMock(return_value=None)
        records_mock.retrieve.return_value = self.ns1_geo_record
        provider._NS1Records = records_mock

        # Test creating the unit.tests zones from scratch.
        provider._zone_cache['unit.tests'] = None
        plan = provider.plan(unit_test_zone)
        provider._reset_cache()

        self.assertFalse(plan.exists)
        self.assertEquals(14, len(plan.changes))
        self.assertEquals(14, provider.apply(plan))
        self.assertEquals(0, zones_mock.retrieve.call_count)
        self.assertEquals(1, zones_mock.create.call_count)
        self.assertEquals(0, records_mock.retrieve.call_count)
        self.assertEquals(14, records_mock.create.call_count)
        self.assertEquals(0, records_mock.update.call_count)

        # Reset everything.
        provider._reset_cache()
        zones_mock.reset_mock()
        records_mock.reset_mock()
        unit_test_zone = octodns_test_zone()

        # Test adding a record.
        unit_test_zone.add_record(Record.new(unit_test_zone, 'ns1', {
            'ttl': 3600,
            'type': 'A',
            'values': ['3.3.3.3']
        }))
        plan = provider.plan(unit_test_zone)

        self.assertTrue(plan.exists)
        self.assertEquals(1, len(plan.changes))
        self.assertEquals(1, provider.apply(plan))
        self.assertEquals(1, zones_mock.retrieve.call_count)
        self.assertEquals(0, zones_mock.create.call_count)
        self.assertEquals(1, records_mock.retrieve.call_count)
        self.assertEquals(1, records_mock.create.call_count)
        self.assertEquals(0, records_mock.update.call_count)
        self.assertEquals(0, records_mock.delete.call_count)

        # Reset everything.
        provider._reset_cache()
        zones_mock.reset_mock()
        records_mock.reset_mock()
        unit_test_zone = octodns_test_zone()

        # Test changing a record.
        remove_octodns_record(unit_test_zone, '', 'A')
        rec = deepcopy(self.ns1_geo_record)
        rec['answers'].append({
            "answer": ["100.100.100.100"],
            "meta": {
                "note": "octodns_region_code:NS-CA-BC",
                "ca_province": ["BC"]
            }
        })
        args = provider._data_for('A', rec)
        unit_test_zone.add_record(Record.new(unit_test_zone, '', args))

        plan = provider.plan(unit_test_zone)
        self.assertTrue(plan.exists)
        self.assertEquals(1, len(plan.changes))
        self.assertEquals(1, provider.apply(plan))
        self.assertEquals(1, zones_mock.retrieve.call_count)
        self.assertEquals(0, zones_mock.create.call_count)
        self.assertEquals(1, records_mock.retrieve.call_count)
        self.assertEquals(0, records_mock.create.call_count)
        self.assertEquals(1, records_mock.update.call_count)
        self.assertEquals(0, records_mock.delete.call_count)

        # Reset everything.
        provider._reset_cache()
        zones_mock.reset_mock()
        records_mock.reset_mock()
        unit_test_zone = octodns_test_zone()

        # Test removing a record.
        zones_mock.retrieve.return_value = self.ns1_zone
        records_mock.retrieve.return_value  = self.ns1_geo_record

        remove_octodns_record(unit_test_zone, 'cname', 'CNAME')
        plan = provider.plan(unit_test_zone)
        self.assertTrue(plan.exists)
        self.assertEquals(1, len(plan.changes))
        self.assertEquals(1, provider.apply(plan))
        self.assertEquals(1, zones_mock.retrieve.call_count)
        self.assertEquals(0, zones_mock.create.call_count)
        self.assertEquals(1, records_mock.retrieve.call_count)
        self.assertEquals(0, records_mock.create.call_count)
        self.assertEquals(0, records_mock.update.call_count)
        self.assertEquals(1, records_mock.delete.call_count)
