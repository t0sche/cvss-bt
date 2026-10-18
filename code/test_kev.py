"""
Tests for loading the CISA KEV catalog: fallback order and rejection of
unusable responses. requests.get is mocked, so no network is used.
"""
from unittest import mock

import pytest
import requests

import enrich_nvd

GOOD = {'catalogVersion': 'test', 'count': 1, 'vulnerabilities': [{'cveID': 'CVE-2021-44228'}]}

BAD_PAYLOADS = [
    {'vulnerabilities': []},
    [],
    {'vulnerabilities': [{}]},
    {'vulnerabilities': {'cveID': 'CVE-2021-44228'}},
    {'vulnerabilities': [{'cveID': 'not-a-cve'}]},
]


def _response(payload):
    response = mock.Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


def _http_error():
    response = mock.Mock()
    response.raise_for_status.side_effect = requests.HTTPError('404')
    return response


def test_primary_used_when_valid():
    with mock.patch.object(enrich_nvd.requests, 'get', return_value=_response(GOOD)) as get:
        assert enrich_nvd.get_kev_data() == GOOD
    assert get.call_args_list[0].args[0] == enrich_nvd.KEV_JSON
    assert get.call_count == 1


def test_fallback_used_on_http_error():
    with mock.patch.object(enrich_nvd.requests, 'get', side_effect=[_http_error(), _response(GOOD)]) as get:
        assert enrich_nvd.get_kev_data() == GOOD
    assert get.call_args_list[1].args[0] == enrich_nvd.KEV_JSON_FALLBACK


@pytest.mark.parametrize('payload', BAD_PAYLOADS)
def test_fallback_used_on_unusable_catalog(payload):
    with mock.patch.object(enrich_nvd.requests, 'get', side_effect=[_response(payload), _response(GOOD)]):
        assert enrich_nvd.get_kev_data() == GOOD


@pytest.mark.parametrize('payload', BAD_PAYLOADS)
def test_raises_when_both_sources_unusable(payload):
    with mock.patch.object(enrich_nvd.requests, 'get', side_effect=[_response(payload), _response(payload)]):
        with pytest.raises(RuntimeError):
            enrich_nvd.get_kev_data()
