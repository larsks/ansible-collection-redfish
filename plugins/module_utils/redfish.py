import jmespath
import logging
import requests
import simplejson

from urllib.parse import urlparse, urljoin

LOG = logging.getLogger()


class RedfishError(Exception):
    pass


class HTTPAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args, timeout=None, verify=None, **kwargs):
        self.timeout = timeout
        self.verify = verify
        super().__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        kwargs['timeout'] = self.timeout
        kwargs['verify'] = self.verify
        return super().send(*args, **kwargs)


class Redfish(requests.Session):
    def __init__(self, baseurl, timeout=None, verify=None, **kwargs):
        self.baseurl = baseurl
        adapter = HTTPAdapter(timeout=timeout,
                              verify=verify)

        super().__init__()
        self.mount('http://', adapter)
        self.mount('https://', adapter)

    def request(self, method, url, **kwargs):
        LOG.warning(f'{method} {url}')
        parts = urlparse(url)
        if not parts.scheme:
            url = urljoin(self.baseurl, url)

        return super().request(method, url, **kwargs)

    def get_resource(self, url, **kwargs):
        try:
            res = self.get(url, **kwargs)
            res.raise_for_status()
            return res.json()
        except requests.exceptions.RequestException as err:
            raise RedfishError('Error fetching resource {}: {}'.format(
                url, err))
        except simplejson.errors.JSONDecodeError as err:
            raise RedfishError('Failed to decode JSON from {}: {}'.format(
                url, err))

    def discover(self):
        return self.get_resource('/redfish/v1')

    def resolve_one(self, data, spec):
        match = jmespath.search(spec['expr'], data)

        if isinstance(match, list):
            data[spec['key']] = items = []
            for item in match:
                items.append(self._resolve(item['@odata.id']))
        elif isinstance(match, dict):
            data[spec['key']] = self._resolve(match['@odata.id'])
        else:
            data[spec['key']] = None

    def resolve(self, data, specs):
        for spec in specs:
            try:
                self.resolve_one(data, spec)
            except jmespath.exceptions.JMESPathError as err:
                raise RedfishError('Error in JMESPATh exception: {}'.format(err)) from None
            except requests.exceptions.RequestException as err:
                raise RedfishError('Error fetching data: {}'.format(err)) from None

    def _resolve(self, url):
        data = self.get_resource(url)

        if 'Members' in data:
            items = []
            for item in data['Members']:
                items.append(self._resolve(item['@odata.id']))
            return items
        else:
            return data
