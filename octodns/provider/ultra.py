#
#
#

from __future__ import absolute_import, division, print_function, \
    unicode_literals

from collections import defaultdict
from ipaddress import IPv4Address, IPv6Address
from requests import Session
import logging
from urlparse import urlsplit
from urllib import urlencode
from time import sleep
import time
import json
import re

from ..zone import Zone
from ..record import Record
from .base import BaseProvider


class UltraClientException(Exception):
    pass


class UltraClientNotFound(UltraClientException):

    def __init__(self):
        super(UltraClientNotFound, self).__init__('Not Found')


class UltraClientUnauthorized(UltraClientException):

    def __init__(self):
        super(UltraClientUnauthorized, self).__init__('Unauthorized')


class UnknownRdatatype(Exception):
    """DNS resource record type is unknown."""


class UltraClient(object):
    BASE = 'https://restapi.ultradns.com/v2'

    NONE = 0
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    NULL = 10
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    NAPTR = 35
    SPF = 99

    _by_text = {
        'NONE': NONE,
        'A': A,
        'NS': NS,
        'CNAME': CNAME,
        'SOA': SOA,
        'AAAA': AAAA,
        'MX': MX,
        'TXT': TXT,
        'NAPTR': NAPTR,
        'SRV': SRV,
        'PTR': PTR,
        'SPF': SPF,
        'NULL': NULL
    }
    _unknown_type_pattern = re.compile('TYPE([0-9]+)$', re.I)

    def __init__(self, account_name, username, password,
                 sleep_period, nameservers=[]):
        self._connected = False
        sess = Session()
        self._sess = sess
        self.token_expires_at = None
        self.account_name = account_name
        self._username = username
        self._password = password
        self.sleep_after_zone_creation = sleep_period
        self.nameservers = nameservers

    def _check_ultra_session(self):
        current_time = time.time()
        if not self.token_expires_at:
            self._connect_session()
        elif self.token_expires_at <= current_time:
            self._refresh_auth_token()

    def _refresh_auth_token(self):
        data = {'grant_type': "refresh_token",
                'refresh_token': self.refresh_token}
        self._execute_auth_request(data)

    def _connect_session(self):
        data = {'grant_type': "password", 'username': self._username,
                'password': self._password}
        self._execute_auth_request(data)

    def is_root_ns_record(self, record):
        return record['rrtype'] == 'NS' and \
            record['rdata'] in self.nameservers

    def _execute_auth_request(self, data):
        try:
            url = '{}{}'.format(self.BASE, "/authorization/token")
            resp = self._sess.request("POST", url, data=urlencode(data))
            if resp.status_code == 401:
                raise UltraClientUnauthorized()
            if resp.status_code == 404:
                raise UltraClientNotFound()
            resp.raise_for_status()
        except Exception as e:
            raise UltraClientException(e)

        try:
            json_data = json.loads(resp.content)
            self.refresh_token = json_data['refreshToken']
            self.access_token = json_data['accessToken']
            # Just adding some padding on the expiration to be safe
            self.token_expires_at = time.time() + \
                float(json_data['expiresIn']) - 120
        except KeyError as e:
            raise UltraClientException(e)
        self._sess.headers.update(
            {'Authorization': 'Bearer {}'.format(self.access_token),
             'Content-Type': 'application/json'})

    def _request(self, method, path, params=None, data=None):
        self._check_ultra_session()
        url = '{}{}'.format(self.BASE, path)
        resp = self._sess.request(method, url, params=params, json=data)
        if resp.status_code == 401:
            raise UltraClientUnauthorized()
        if resp.status_code == 404:
            raise UltraClientNotFound()
        resp.raise_for_status()
        return resp

    def from_text(self, text):
        """Convert text into a DNS rdata type value.
        The input text can be a defined DNS RR type mnemonic or
        instance of the DNS generic type syntax.
        For example, "NS" and "TYPE2" will both result in a value of 2.
        Raises ``dns.rdatatype.UnknownRdatatype`` if the type is unknown.
        Raises ``ValueError`` if the rdata type value is not >= 0 and <= 65535.
        Returns an ``int``.
        """

        value = self._by_text.get(text.upper())
        if value is None:
            match = self._unknown_type_pattern.match(text)
            if match is None:
                raise UnknownRdatatype
            value = int(match.group(1))
            if value < 0 or value > 65535:
                raise ValueError("type must be between >= 0 and <= 65535")
        return value

    def format_rrtype_from_text(self, _type):
        return "{} ({})".format(_type.upper(), self.from_text(_type))

    def domain(self, name):
        path = '/zones/{}'.format(name)
        return self._request('GET', path).json()

    def domain_create(self, name):
        data = {
            'properties': {
                'name': name,
                'accountName': self.account_name,
                'type': 'PRIMARY'
            },
            "primaryCreateInfo": {
                "forceImport": True,
                "createType": "NEW"
            }
        }
        self._request('POST', '/zones', data=data)
        # UltraDNS needs a little bit of time after zone
        #      creation before we can request the records
        sleep(self.sleep_after_zone_creation)
        zone = Zone(name, [])
        records = self.records(zone)
        for record in records:
            if record['rrtype'] == 'SOA' or record['rrtype'] == 'NS':
                continue
            self.record_delete(name, record)

    def _is_valid_ip_value(self, version, value):
        if version == 'ipv6':
            try:
                IPv6Address(unicode(value))
            except Exception:
                return False
        else:
            try:
                IPv4Address(unicode(value))
            except Exception:
                return False

        return True

    def records(self, zone):
        zone_name = zone.name
        path = '/zones/{}/rrsets'.format(zone_name)
        ret = []

        offset = 0
        limit = 500
        while True:
            data = self._request('GET', path,
                                 {'offset': offset, 'limit': limit}).json()

            ret += data['rrSets']
            # https://ultra-portalstatic.ultradns.com/static/docs/REST-API_User_Guide.pdf
            # pages exists if there is more than 1 page
            # last doesn't exist if you're on the last page
            # "resultInfo":{"totalCount":13,"offset":10,"returnedCount":3}}
            try:
                info = data['resultInfo']
                total_count = int(info['totalCount'])
                info_offset = int(info['offset'])
                returned_count = int(info['returnedCount'])

                if info_offset + returned_count >= total_count:
                    break

                offset += limit
            except KeyError:
                break

        regex = r"([\w]+)\s+\([\d]+\)"
        for record in ret:
            # parse the type and only keep the real type
            # from CNAME (5) to cname
            m = re.match(regex, record['rrtype'])
            record['rrtype'] = m.group(1)
            record['ownerName'] = zone.hostname_from_fqdn(record['ownerName'])
            if record['rrtype'].upper() == 'A' and 'profile' in record and\
               record['profile']['@context'] ==\
               "http://schemas.ultradns.com/DirPool.jsonschema":
                data = record['rdata']
                t = record['rrtype']
                v = data[0] if isinstance(data, list) else data
                if not self._is_valid_ip_value('ipv4', v) and \
                   not self._is_valid_ip_value('ipv6', v):
                    t = 'CNAME'
                record['rrtype'] = t
            elif 'profile' in record and\
                 record['profile']['@context'] ==\
                 "http://schemas.ultradns.com/SBPool.jsonschema":
                # We need to retrieve the probes
                ownerName = record['ownerName']
                path = "/zones/{}/rrsets/A/{}/probes".format(zone_name,
                                                             ownerName)
                try:
                    probes = self._request('GET', path,
                                           {'offset': offset,
                                            'limit': limit}).json()
                    if 'probes' in probes:
                        record['probes'] = probes['probes']
                except:
                    pass

        return ret

    def record_create(self, zone_name, params):
        type_str = params['rrtype']
        params['rrtype'] = self.format_rrtype_from_text(type_str)
        path = '/zones/{}/rrsets/{}/{}'.format(zone_name,
                                               type_str.upper(),
                                               params['ownerName'])
        self._request('POST', path, data=params)
        if 'probes' in params:
            path = "{}/probes".format(path)
            self._request('POST', path, data=params['probes'])

    def record_update(self, zone_name, params):
        type_str = params['rrtype']
        params['rrtype'] = self.format_rrtype_from_text(type_str)
        path = '/zones/{}/rrsets/{}/{}'.format(zone_name,
                                               type_str.upper(),
                                               params['ownerName'])
        self._request('PUT', path, data=params)

    def record_delete(self, zone_name, r):
        try:
            t = r['rrtype'] if 'rrtype' in r else r._type
            n = r['ownerName'] if 'ownerName' in r else r.name
        except TypeError:
            t = r._type
            n = r.name

        if t.upper() == 'CNAME':
            try:
                if len(r.geo) > 0:
                    # if record has a geo block, check if values are ip or not
                    # cname has value and A has values
                    t = 'A'
            except AttributeError:
                t = t

        n = zone_name if not n else n
        path = '/zones/{}/rrsets/{}/{}'.format(zone_name,
                                               t.upper(),
                                               n)
        self._request('DELETE', path)


class UltraProvider(BaseProvider):
    '''
    Ultra DNS provider using API v2

    ultra:
        class: octodns.provider.ultra.UltraProvider
        # Your ultradns username (required)
        username: user
        # Your ultradns password (required)
        password: pass
    '''
    SUPPORTS_GEO = True
    SUPPORTS = set(('A', 'Sitebacker', 'AAAA', 'CAA', 'CNAME', 'MX', 'NS',
                    'TXT', 'SRV', 'NAPTR', 'SPF'))

    ALPHA32 = {
        'NAM': 'NA',
        'SAM': 'SA',
        'EUR': 'EU',
        'AFR': 'AF',
        'ASI': 'AS',
        'OCN': 'OC',
        'ANT': 'AN'
    }

    ALPHA23 = {
        'NA': 'NAM',
        'SA': 'SAM',
        'EU': 'EUR',
        'AF': 'AFR',
        'AS': 'ASI',
        'OC': 'OCN',
        'AN': 'ANT'
    }

    # $ ./ud-list-all-territories.py | jq -r '.[0] | .[].code'
    #        | xargs -n1 -I{} bash -c "echo -n '{}: ';
    #                               ./ud-list-all-territories.py -c {} |
    #                               jq '.[0] | . | map(.code) | join(\",\")'"
    # A1: ""
    # A2: ""
    # A3: ""
    # NAM: "AI,AG,AW,BS,BB,BZ,BM,VG,CA,KY,CR,CU,CW,DM,
    #       DO,BQ,SV,GL,GD,GP,GT,HT,HN,JM,
    #       MQ,MX,MS,AN,NI,PA,PR,BL,MF,PM,VC,SX,KN,LC,TT,TC,VI,U3,US"
    # SAM: "AR,BO,BR,CL,CO,EC,FK,GF,GY,PY,PE,GS,SR,U4,UY,VE"
    # EUR: "AX,AL,AD,AM,AT,AZ,BY,BE,BA,BG,HR,CZ,DK,EE,FO,FI
    #       ,FR,GE,DE,GI,GR,GG,HU,IS,
    #       IE,IM,IT,JE,LV,LI,LT,LU,MK,MT,MD,MC,ME,NL,NO,PL,PT,
    #       RO,SM,RS,SK,SI,ES,SJ,
    #       SE,CH,UA,U5,GB,VA"
    # AFR: "DZ,AO,BJ,BW,BF,BI,CM,CV,CF,TD,KM,CG,CI,CD,DJ,EG,GQ,
    #       ER,ET,GA,GM,GH,GN,GW,
    #       KE,LS,LR,LY,MG,MW,ML,MR,MU,YT,MA,MZ,NA,NE,NG,RE,RW,
    #       ST,SN,SC,SL,SO,ZA,SS,
    #       SH,SD,SZ,TZ,TG,TN,UG,U7,EH,ZM,ZW"
    # ASI: "AF,BH,BD,BT,IO,BN,KH,CN,CY,HK,IN,ID,IR,IQ,IL,JP,JO,
    #       KZ,KP,KR,KW,KG,LA,LB,
    #       MO,MY,MV,MN,MM,NP,OM,PK,PS,PH,QA,RU,SA,SG,LK,SY,TW,
    #       TJ,TH,TL,TR,TM,U8,U6,
    #       AE,UZ,VN,YE"
    # OCN: "AS,AU,CX,CC,CK,FJ,PF,GU,HM,KI,MH,FM,NR,NC,NZ,NU,NF,
    #       MP,PW,PG,PN,WS,SB,TK,
    #       TO,TV,U9,UM,VU,WF"
    # ANT: "AQ,BV,TF"

    # ./ud-list-all-territories.py | jq -r '.[0] | .[].code'
    #                  | xargs -n1 -I{}
    #              bash -c "./ud-list-all-territories.py -c {}
    #                  | jq '.[0] | .[].code'
    #                  | xargs -n1 -I% echo '\"%\": \"{}\",'"

    _continent_by_country = {
        "AI": "NAM",
        "AG": "NAM",
        "AW": "NAM",
        "BS": "NAM",
        "BB": "NAM",
        "BZ": "NAM",
        "BM": "NAM",
        "VG": "NAM",
        "CA": "NAM",
        "KY": "NAM",
        "CR": "NAM",
        "CU": "NAM",
        "CW": "NAM",
        "DM": "NAM",
        "DO": "NAM",
        "BQ": "NAM",
        "SV": "NAM",
        "GL": "NAM",
        "GD": "NAM",
        "GP": "NAM",
        "GT": "NAM",
        "HT": "NAM",
        "HN": "NAM",
        "JM": "NAM",
        "MQ": "NAM",
        "MX": "NAM",
        "MS": "NAM",
        "AN": "NAM",
        "NI": "NAM",
        "PA": "NAM",
        "PR": "NAM",
        "BL": "NAM",
        "MF": "NAM",
        "PM": "NAM",
        "VC": "NAM",
        "SX": "NAM",
        "KN": "NAM",
        "LC": "NAM",
        "TT": "NAM",
        "TC": "NAM",
        "VI": "NAM",
        "U3": "NAM",
        "US": "NAM",
        "AR": "SAM",
        "BO": "SAM",
        "BR": "SAM",
        "CL": "SAM",
        "CO": "SAM",
        "EC": "SAM",
        "FK": "SAM",
        "GF": "SAM",
        "GY": "SAM",
        "PY": "SAM",
        "PE": "SAM",
        "GS": "SAM",
        "SR": "SAM",
        "U4": "SAM",
        "UY": "SAM",
        "VE": "SAM",
        "AX": "EUR",
        "AL": "EUR",
        "AD": "EUR",
        "AM": "EUR",
        "AT": "EUR",
        "AZ": "EUR",
        "BY": "EUR",
        "BE": "EUR",
        "BA": "EUR",
        "BG": "EUR",
        "HR": "EUR",
        "CZ": "EUR",
        "DK": "EUR",
        "EE": "EUR",
        "FO": "EUR",
        "FI": "EUR",
        "FR": "EUR",
        "GE": "EUR",
        "DE": "EUR",
        "GI": "EUR",
        "GR": "EUR",
        "GG": "EUR",
        "HU": "EUR",
        "IS": "EUR",
        "IE": "EUR",
        "IM": "EUR",
        "IT": "EUR",
        "JE": "EUR",
        "LV": "EUR",
        "LI": "EUR",
        "LT": "EUR",
        "LU": "EUR",
        "MK": "EUR",
        "MT": "EUR",
        "MD": "EUR",
        "MC": "EUR",
        "ME": "EUR",
        "NL": "EUR",
        "NO": "EUR",
        "PL": "EUR",
        "PT": "EUR",
        "RO": "EUR",
        "SM": "EUR",
        "RS": "EUR",
        "SK": "EUR",
        "SI": "EUR",
        "ES": "EUR",
        "SJ": "EUR",
        "SE": "EUR",
        "CH": "EUR",
        "UA": "EUR",
        "U5": "EUR",
        "GB": "EUR",
        "VA": "EUR",
        "DZ": "AFR",
        "AO": "AFR",
        "BJ": "AFR",
        "BW": "AFR",
        "BF": "AFR",
        "BI": "AFR",
        "CM": "AFR",
        "CV": "AFR",
        "CF": "AFR",
        "TD": "AFR",
        "KM": "AFR",
        "CG": "AFR",
        "CI": "AFR",
        "CD": "AFR",
        "DJ": "AFR",
        "EG": "AFR",
        "GQ": "AFR",
        "ER": "AFR",
        "ET": "AFR",
        "GA": "AFR",
        "GM": "AFR",
        "GH": "AFR",
        "GN": "AFR",
        "GW": "AFR",
        "KE": "AFR",
        "LS": "AFR",
        "LR": "AFR",
        "LY": "AFR",
        "MG": "AFR",
        "MW": "AFR",
        "ML": "AFR",
        "MR": "AFR",
        "MU": "AFR",
        "YT": "AFR",
        "MA": "AFR",
        "MZ": "AFR",
        "NA": "AFR",
        "NE": "AFR",
        "NG": "AFR",
        "RE": "AFR",
        "RW": "AFR",
        "ST": "AFR",
        "SN": "AFR",
        "SC": "AFR",
        "SL": "AFR",
        "SO": "AFR",
        "ZA": "AFR",
        "SS": "AFR",
        "SH": "AFR",
        "SD": "AFR",
        "SZ": "AFR",
        "TZ": "AFR",
        "TG": "AFR",
        "TN": "AFR",
        "UG": "AFR",
        "U7": "AFR",
        "EH": "AFR",
        "ZM": "AFR",
        "ZW": "AFR",
        "AF": "ASI",
        "BH": "ASI",
        "BD": "ASI",
        "BT": "ASI",
        "IO": "ASI",
        "BN": "ASI",
        "KH": "ASI",
        "CN": "ASI",
        "CY": "ASI",
        "HK": "ASI",
        "IN": "ASI",
        "ID": "ASI",
        "IR": "ASI",
        "IQ": "ASI",
        "IL": "ASI",
        "JP": "ASI",
        "JO": "ASI",
        "KZ": "ASI",
        "KP": "ASI",
        "KR": "ASI",
        "KW": "ASI",
        "KG": "ASI",
        "LA": "ASI",
        "LB": "ASI",
        "MO": "ASI",
        "MY": "ASI",
        "MV": "ASI",
        "MN": "ASI",
        "MM": "ASI",
        "NP": "ASI",
        "OM": "ASI",
        "PK": "ASI",
        "PS": "ASI",
        "PH": "ASI",
        "QA": "ASI",
        "RU": "ASI",
        "SA": "ASI",
        "SG": "ASI",
        "LK": "ASI",
        "SY": "ASI",
        "TW": "ASI",
        "TJ": "ASI",
        "TH": "ASI",
        "TL": "ASI",
        "TR": "ASI",
        "TM": "ASI",
        "U8": "ASI",
        "U6": "ASI",
        "AE": "ASI",
        "UZ": "ASI",
        "VN": "ASI",
        "YE": "ASI",
        "AS": "OCN",
        "AU": "OCN",
        "CX": "OCN",
        "CC": "OCN",
        "CK": "OCN",
        "FJ": "OCN",
        "PF": "OCN",
        "GU": "OCN",
        "HM": "OCN",
        "KI": "OCN",
        "MH": "OCN",
        "FM": "OCN",
        "NR": "OCN",
        "NC": "OCN",
        "NZ": "OCN",
        "NU": "OCN",
        "NF": "OCN",
        "MP": "OCN",
        "PW": "OCN",
        "PG": "OCN",
        "PN": "OCN",
        "WS": "OCN",
        "SB": "OCN",
        "TK": "OCN",
        "TO": "OCN",
        "TV": "OCN",
        "U9": "OCN",
        "UM": "OCN",
        "VU": "OCN",
        "WF": "OCN",
        "AQ": "ANT",
        "BV": "ANT",
        "TF": "ANT"
    }

    _intervals_from_text = {
        "HALF_MINUTE": 30,
        "ONE_MINUTE": 60,
        "TWO_MINUTES": 120,
        "FIVE_MINUTES": 300,
        "TEN_MINUTES": 600,
        "FIFTEEN_MINUTES": 900,
    }

    _intervals_from_duration = {
        30: "HALF_MINUTE",
        60: "ONE_MINUTE",
        120: "TWO_MINUTES",
        300: "FIVE_MINUTES",
        600: "TEN_MINUTES",
        900: "FIFTEEN_MINUTES",
    }

    def __init__(self, id, account_name, username, password,
                 sleep_period, nameservers=[], *args, **kwargs):
        self.log = logging.getLogger('UltraProvider[{}]'.format(id))
        self.log.debug('__init__: id=%s, token=***', id)
        super(UltraProvider, self).__init__(id, *args, **kwargs)
        self.username = username
        self.password = password
        self.account_name = account_name
        self.nameservers = nameservers
        self._client = UltraClient(account_name, username,
                                   password, sleep_period, nameservers)
        self._zone_records = {}

    def _healthcheck_data_for_HTTP(self, profile, probe):
        try:
            url = probe['details']['transactions'][0]['url']
        except:
            return [1, 80, '/']
        url_components = urlsplit(url)
        path = url_components.path
        query = url_components.query
        path = path if not query else path + "?" + query

        if url_components.port:
            port = url_components.port
        else:
            port = 80 if url.startswith('http://') else 443

        retries = probe['threshold']
        probe_type = "HTTP" if url.startswith('http://') else "HTTPS"

        return [retries, url_components.hostname, port, path, probe_type]

    def _healthcheck_data_for_TCP(self, profile, probe):
        try:
            port = probe['details']['port']
        except:
            port = None
        retries = probe['threshold']

        return [retries, None, port, None, None]

    def _parse_healthcheck_data(self, record):
        profile = record['profile']
        try:
            monitor = record['probes'][0]
        except:
            return {}

        backup = profile['backupRecords'][0]['rdata']
        probe_type = monitor['type']
        data_for = getattr(self, '_healthcheck_data_for_{}'.format(probe_type))
        retries, host, port, path, pt = data_for(profile, monitor)

        ret = {
            'path': path,
            'host': host,
            'backup': backup,
            'interval': self._intervals_from_text[monitor['interval']],
            'port': port,
            'retries': retries,
            'type': pt if pt else probe_type,
        }
        return {k: v for k, v in ret.items() if v is not None}

    def _sbpool_data_for_multiple(self, _type, records):
        record = records[0]
        healthcheck = self._parse_healthcheck_data(record)

        return {
            'ttl': record['ttl'],
            'type': 'Sitebacker',
            'values': record['rdata'],
            'healthcheck': healthcheck
        }

    _sbpool_data_for_A = _sbpool_data_for_multiple
    _sbpool_data_for_AAAA = _sbpool_data_for_multiple

    geo_re = re.compile(r'^(?P<continent_code>\w\w\w?)(-(?P<country_code>\w\w)'
                        r'(-(?P<subdivision_code>\w\w))?)?$')

    def _parse_geo_data(self, records):
        record = records[0]
        rdata_info = record['profile']['rdataInfo']
        num_region = len(record['rdata'])
        catch_all = {}
        ttl = 0
        geos = {}

        for i in range(num_region):
            info = rdata_info[i]
            if ttl == 0 or ('ttl' in info and info['ttl'] < ttl):
                ttl = info['ttl']
            if 'geoInfo' in info:
                ip = record['rdata'][i]
                for code in info['geoInfo']['codes']:
                    match = self.geo_re.match(code)
                    continent_code = match.group('continent_code')
                    country_code = match.group('country_code')
                    subdivision_code = match.group('subdivision_code')
                    if (continent_code and country_code and
                       not subdivision_code) or (
                       continent_code and not country_code and
                       not subdivision_code and len(continent_code) == 2):
                        subdivision_code = country_code
                        country_code = continent_code
                        continent_code = None
                    if continent_code:
                        continent_code = self.ALPHA32[continent_code]
                    else:
                        if country_code == "A1" or country_code == "A2" \
                           or country_code == "A3":
                            continent_code = country_code
                            country_code = None
                        else:
                            continent_code =\
                                self._continent_by_country[country_code]
                            continent_code = self.ALPHA32[continent_code]

                    code = continent_code
                    code = "{}-{}".format(code, country_code)\
                           if country_code else code
                    code = "{}-{}".format(code, subdivision_code)\
                           if subdivision_code else code
                    geos[code] = [ip]
            elif 'allNonConfigured' in info:
                catch_all = record['rdata'][i]

        return [catch_all, ttl, geos]

    def _geo_data_for_multiple(self, _type, records):
        catch_all, ttl, geos = self._parse_geo_data(records)

        r = {
            'ttl': ttl,
            'type': _type,
            'values': [catch_all],
            'geo': geos
        }
        return r

    _geo_data_for_A = _geo_data_for_multiple
    _geo_data_for_AAAA = _geo_data_for_multiple

    def _geo_data_for_TXT(self, _type, records):
        records[0]['rdata'] = [self._fix_semicolons.sub('\;', rr)
                               for rr in records[0]['rdata']]

        return self._geo_data_for_multiple(_type, records)

    def _geo_data_for_single(self, _type, records):
        catch_all, ttl, geos = self._parse_geo_data(records)

        r = {
            'ttl': ttl,
            'type': _type,
            'value': catch_all,
            'geo': geos
        }
        return r

    _geo_data_for_CNAME = _geo_data_for_single

    def _data_for_multiple(self, _type, records):
        record = records[0]

        return {
            'ttl': record['ttl'],
            'type': _type,
            'values': record['rdata']
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_NS = _data_for_multiple

    _fix_semicolons = re.compile(r'(?<!\\);')

    def _data_for_TXT(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': [self._fix_semicolons.sub('\;', rr)
                       for rr in records[0]['rdata']]
        }

    _data_for_SPF = _data_for_TXT

    def _data_for_CNAME(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'value': records[0]['rdata'][0]
        }

    def _data_for_CAA(self, _type, records):
        values = []
        for record in records:
            flags, tag, value = record['rdata'][0].split(' ')
            values.append({
                'flags': flags,
                'tag': tag,
                'value': value[1:-1],
            })
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': values
        }

    def _data_for_MX(self, _type, records):
        values = []
        for record in records:
            for value in record['rdata']:
                preference, exchange = value.split(' ')
                values.append({
                    'preference': preference,
                    'exchange': exchange,
                })
        return {
            'ttl': records[0]['ttl'],
            'type': _type,
            'values': values
        }

    def _data_for_NAPTR(self, _type, rrset):
        values = []
        for rr in rrset['ResourceRecords']:
            order, preference, flags, service, regexp, replacement = \
                rr['rdata'][0].split(' ')
            flags = flags[1:-1]
            service = service[1:-1]
            regexp = regexp[1:-1]
            values.append({
                'order': order,
                'preference': preference,
                'flags': flags,
                'service': service,
                'regexp': regexp,
                'replacement': replacement,
            })
        return {
            'type': _type,
            'values': values,
            'ttl': int(rrset[0]['ttl'])
        }

    def _data_for_SRV(self, _type, records):
        values = []
        for record in records:
            priority, weight, port, target = record['rdata'][0].split(' ')
            values.append({
                'priority': priority,
                'weight': weight,
                'port': port,
                'target': target,
            })
        return {
            'type': _type,
            'ttl': records[0]['ttl'],
            'values': values
        }

    def zone_records(self, zone):
        if zone.name not in self._zone_records:
            try:
                self._zone_records[zone.name] = \
                    self._client.records(zone)
            except UltraClientNotFound:
                return []

        return self._zone_records[zone.name]

    def populate(self, zone, target=False, lenient=False):
        self.log.debug('populate: name=%s, target=%s, lenient=%s', zone.name,
                       target, lenient)

        exists = False
        values = defaultdict(lambda: defaultdict(list))
        for record in self.zone_records(zone):
            exists = True
            _type = record['rrtype']
            record_name = record['ownerName']
            values[record_name][_type].append(record)

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                if _type == 'SOA':
                    continue
                if 'profile' in records[0] and\
                   records[0]['profile']['@context'] ==\
                   "http://schemas.ultradns.com/DirPool.jsonschema":
                    data_for = getattr(self, '_geo_data_for_{}'.format(_type))
                elif 'profile' in records[0] and\
                     records[0]['profile']['@context'] ==\
                     "http://schemas.ultradns.com/SBPool.jsonschema":
                    data_for = getattr(self,
                                       '_sbpool_data_for_{}'.format(_type))
                else:
                    data_for = getattr(self, '_data_for_{}'.format(_type))
                record = Record.new(zone, name, data_for(_type, records),
                                    source=self, lenient=lenient)
                zone.add_record(record)

        self.log.info('populate:   found %s records, exists=%s',
                      len(zone.records) - before, exists)

        return exists

    def _generate_profile_sbpool(self, hltck):
        return {
            "@context":
            "http://schemas.ultradns.com/SBPool.jsonschema",
            "maxActive": 1,
            "actOnProbes": True,
            "order": "FIXED",
            "backupRecords": [{
                "failoverDelay": 0,
                "rdata": hltck['backup']
            }],
            "rdataInfo": [{
                "runProbes": True,
                "priority": 1,
                "threshold": 1,
                "failoverDelay": 0
            }]
        }

    def _process_healthcheck_interval(self, interval):
        valid_intervals = list(self._intervals_from_duration.keys())
        period = min(valid_intervals,
                     key=lambda x: abs(int(x) - int(interval)))
        return self._intervals_from_duration[period]

    def _generate_probes_sbpool_for_http_https(self, protocol, hltck):
        interval = self._process_healthcheck_interval(hltck['interval'])
        return {
            "interval": interval,
            "agents": [
                "NEW_YORK", "PALO_ALTO",
                "DALLAS", "AMSTERDAM"
            ],
            "details": {
                "totalLimits": {"fail": 5},
                "transactions": [{
                    "url": "{}://{}:{}{}".format(protocol, hltck['host'],
                                                 hltck['port'], hltck['path']),
                    "method": "GET",
                    "limits": {
                        "run": {"fail": 5},
                        "connect": {"fail": 5}
                    },
                    "followRedirects": True
                }]
            },
            "threshold": hltck['retries'],
            "type": "HTTP"
        }

    def _generate_probes_sbpool_for_HTTPS(self, hltck):
        if 'port' not in hltck:
            hltck['port'] = 443
        return self._generate_probes_sbpool_for_http_https('https', hltck)

    def _generate_probes_sbpool_for_HTTP(self, hltck):
        if 'port' not in hltck:
            hltck['port'] = 80
        return self._generate_probes_sbpool_for_http_https('http', hltck)

    def _generate_probes_sbpool_for_TCP(self, hltck):
        return {
            "interval": self._intervals_from_duration[hltck['interval']],
            "agents": [
                "NEW_YORK", "PALO_ALTO",
                "DALLAS", "AMSTERDAM"
            ],
            "details": {
                "port": hltck['port'],
                "limits": {"connect": {"fail": 10}}
            },
            "threshold": hltck['retries'],
            "type": "TCP"
        }

    def _generate_probes_sbpool(self, hltck):
        function_prefix = '_generate_probes_sbpool_for_'
        data_for = getattr(self,
                           '{}{}'.format(function_prefix, hltck['type']))
        return data_for(hltck)

    def _healthcheck_params_for_multiple(self, record):
        params_for_str = '_params_for_{}'.format(record._type)
        params_for = getattr(self, params_for_str)
        for params in params_for(record):
            hltck = record.healthcheck
            profile = self._generate_profile_sbpool(hltck)
            probes = self._generate_probes_sbpool(hltck)
            data = {
                'profile': profile,
                'probes': probes,
                'rrtype': 'A' if record._type == 'Sitebacker'
                          else record._type,
                'rdata': record.values
            }
            yield dict(params, **data)

    _healthcheck_params_for_A = _healthcheck_params_for_multiple
    _healthcheck_params_for_AAAA = _healthcheck_params_for_multiple

    def _generate_rdata_dirpool(self, record):
        rdata = []
        rdata_info = []
        for ident, geo in record.geo.items():
            code = "" if geo.country_code else self.ALPHA23[geo.continent_code]
            if geo.country_code:
                code = geo.country_code
            if geo.subdivision_code:
                code = "{}-{}".format(code, geo.subdivision_code)
            geo_info = {
                "codes": [code],
                "name": ident
            }
            try:
                value = geo.values[0]
            except AttributeError:
                value = geo.value
            rdata.append(value)
            rdata_info.append({"geoInfo": geo_info})

        # generate AllNonConfigured
        try:
            default_value = record.values[0]
        except AttributeError:
            default_value = record.value
        rdata.append(default_value)
        rdata_info.append({'allNonConfigured': True})

        return [rdata_info, rdata]

    def _geo_params_for_multiple(self, record):
        params_for_str = '_params_for_{}'.format(record._type)
        params_for = getattr(self, params_for_str)
        for params in params_for(record):
            rdata_info, rdata = self._generate_rdata_dirpool(record)
            data = {
                "profile": {
                    "@context":
                    "http://schemas.ultradns.com/DirPool.jsonschema",
                    "description": record.name,
                    "rdataInfo": rdata_info
                },
                "rdata": rdata,
                # Ultra doesn't support RDPool on CNAME but an A RDPool
                #       can accept CNAMEs
                "rrtype": "A" if params['rrtype'] == 'CNAME'\
                          else params['rrtype']
            }
            yield dict(params, **data)

    _geo_params_for_A = _geo_params_for_multiple
    _geo_params_for_AAAA = _geo_params_for_multiple
    _geo_params_for_CNAME = _geo_params_for_multiple

    def _geo_params_for_TXT(self, record):
        record.values = [v.replace('\;', ';') for v in record.chunked_values]
        return self._geo_params_for_multiple(record)

    def _geo_params_todo(self, record):
        raise ValueError('Not implemented for this record type yet')

    _geo_params_for_PTR = _geo_params_todo
    _geo_params_for_HINFO = _geo_params_todo
    _geo_params_for_MX = _geo_params_todo
    _geo_params_for_RP = _geo_params_todo
    _geo_params_for_SRV = _geo_params_todo
    _geo_params_for_NAPTR = _geo_params_todo
    _geo_params_for_SPF = _geo_params_todo

    def _params_for_multiple(self, record):
        yield {
            'ttl': record.ttl,
            'ownerName': record.name,
            'rrtype': record._type,
            'rdata': record.values
        }

    def _params_for_multiple_ips(self, record):
        if len(record.values) > 1:
            yield {
                'ttl': record.ttl,
                'ownerName': record.name,
                'rrtype': record._type,
                'rdata': record.values,
                'profile': {
                    '@context':
                        'http://schemas.ultradns.com/RDPool.jsonschema',
                    'order': 'ROUND_ROBIN',
                    'description': record.name
                }
            }
        else:
            yield {
                'ttl': record.ttl,
                'ownerName': record.name,
                'rrtype': record._type,
                'rdata': record.values
            }

    _params_for_A = _params_for_multiple_ips
    _params_for_AAAA = _params_for_multiple_ips
    _params_for_NS = _params_for_multiple

    def _params_for_TXT(self, record):
        values = [v.replace('\;', ';') for v in record.chunked_values]
        ret = []
        for v in values:
            if v and v[0] == '"':
                v = v[1:-1]
            ret.append(v.replace('" "', ''))
        yield {
            'ttl': record.ttl,
            'ownerName': record.name,
            'rrtype': record._type,
            'rdata': ret
        }

    _params_for_SPF = _params_for_TXT

    def _params_for_CAA(self, record):
        yield {
            'ttl': record.ttl,
            'ownerName': record.name,
            'rrtype': record._type,
            'rdata': ['{} {} "{}"'.format(v.flags, v.tag, v.value)
                      for v in record.values]
        }

    def _params_for_single(self, record):
        yield {
            'rdata': [record.value],
            'ownerName': record.name,
            'ttl': record.ttl,
            'rrtype': record._type
        }

    _params_for_CNAME = _params_for_single

    def _params_for_MX(self, record):
        yield {
            'ttl': record.ttl,
            'ownerName': record.name,
            'rrtype': record._type,
            'rdata': ['{} {}'.format(v.preference, v.exchange)
                      for v in record.values]
        }

    def _params_for_SRV(self, record):
        yield {
            'ttl': record.ttl,
            'ownerName': record.name,
            'rrtype': record._type,
            'rdata': ['{} {} {} {}'.format(v.priority, v.weight, v.port,
                                           v.target)
                      for v in record.values]
        }

    def _params_for_NAPTR(self, record):
        yield {
            'ttl': record.ttl,
            'ownerName': record.name,
            'rrtype': record._type,
            'rdata': ['{} {} "{}" "{}" "{}" {}'
                      .format(v.order, v.preference,
                              v.flags if v.flags else '',
                              v.service if v.service else '',
                              v.regexp if v.regexp else '',
                              v.replacement)
                      for v in record.values]
        }

    def _compute_paramsfor_name(self, change):
        new = change.new
        if getattr(change.new, 'geo', False) or getattr(change.existing,
                                                        'geo', False):
            return '_geo_params_for_{}'.format(new._type)
        if getattr(change.new, 'healthcheck', False) or \
           getattr(change.existing, 'healthcheck', False):
            return '_healthcheck_params_for_{}'.format(new._type)

        return '_params_for_{}'.format(new._type)

    def _apply_Create(self, change):
        new = change.new
        if new._type == 'NS' and new.name == '':
            self._apply_Update_For_Real(change)
        else:
            params_for_str = self._compute_paramsfor_name(change)
            params_for = getattr(self, params_for_str)
            for params in params_for(new):
                if params['ownerName'] == '':
                    params['ownerName'] = new.zone.name
                self._client.record_create(new.zone.name, params)

    def _apply_Update_For_Real(self, change):
        new = change.new
        params_for_str = self._compute_paramsfor_name(change)
        params_for = getattr(self, params_for_str)
        for params in params_for(new):
            if params['ownerName'] == '':
                params['ownerName'] = new.zone.name
            self._client.record_update(new.zone.name, params)

    def _apply_Update(self, change):
        existing = change.existing
        if existing._type == 'NS':
            self._apply_Update_For_Real(change)
        else:
            self._apply_Delete(change)
            self._apply_Create(change)

    def _apply_Delete(self, change):
        existing = change.existing
        zone = existing.zone
        for record in self.zone_records(zone):
            if existing.name == record['ownerName'] and\
               existing._type == record['rrtype'] and\
               not self._client.is_root_ns_record(record):
                if existing.name == '':
                    existing.name = zone.name
                self._client.record_delete(zone.name, existing)

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug('_apply: zone=%s, len(changes)=%d', desired.name,
                       len(changes))

        domain_name = desired.name
        try:
            self._client.domain(domain_name)
        except UltraClientException:
            self.log.debug('_apply:   no matching zone, creating domain')
            self._client.domain_create(domain_name)

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, '_apply_{}'.format(class_name))(change)

        # Clear out the cache if any
        self._zone_records.pop(desired.name, None)
