import dataclasses
import json
from dataclasses import dataclass
from typing import List

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

s = requests.Session()

retries = Retry(
    total=7,
    backoff_factor=0.1,
    status_forcelist=[500, 502, 503, 504],
)

# noinspection HttpUrlsUsage
s.mount('http://', HTTPAdapter(max_retries=retries))
s.mount('https://', HTTPAdapter(max_retries=retries))


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)


@dataclass
class Institution:
    name: str
    source_url: str
    block_ips: List[str]


@dataclass
class Domain:
    domain: str
    status: int
    ips: List[str]


@dataclass
class InstitutionWithDomains:
    institution: Institution
    resolved_domains: List[Domain]


institutions = [
    Institution(
        name='Lietuvos bankas',
        source_url='https://lpt.lrv.lt/uploads/lpt/documents/files/neleg.txt',
        block_ips=['193.219.8.149'],
    ),
    Institution(
        name='Lošimai',
        source_url='https://lpt.lrv.lt/uploads/lpt/documents/files/neleg.txt',
        block_ips=['62.77.154.37'],
    ),

    Institution(
        name='RTK',
        source_url='https://www.rtk.lt/uploads/documents/files/atviri-duomenys/neteisetos-veiklos-vykdytojai/svetaines_pazeidziancios_autoriu_teises_20211222.txt',
        block_ips=['88.119.87.40', '92.61.36.174'],
    ),
    Institution(
        name='VVTAT',
        source_url='https://www.vvtat.lt/data/public/uploads/2020/10/blokuojami-tinklapiai.txt',
        block_ips=['193.219.10.98'],
    ),
]


def resolve_domain(domain: str) -> Domain:
    params = {
        'name': domain,
        'type': 'A',
    }
    ae = s.get('https://dns.google/resolve', params=params)

    ae.raise_for_status()

    js = ae.json()

    ips = [answer['data'] for answer in js.get('Answer', [])]

    return Domain(
        domain=domain,
        status=js['Status'],
        ips=list(ips),
    )


def resolve_domains(domains: List[str]) -> List[Domain]:
    for domain in domains:
        yield resolve_domain(domain)


def fetch_institution_domains(institution: Institution) -> List[str]:
    r = s.get(institution.source_url)
    r.raise_for_status()

    return [line.strip() for line in r.text.split('\n') if line.strip()]


def create_blocked_domains_lists() -> List[InstitutionWithDomains]:
    for institution in institutions:
        domains = fetch_institution_domains(institution)
        resolved_domains = list(resolve_domains(domains))

        yield InstitutionWithDomains(
            institution=institution,
            resolved_domains=resolved_domains
        )


def write_blocked_domain_files():
    blocked_domains_lists = list(create_blocked_domains_lists())

    with open('isp-blocked-domains.min.json', 'w') as outfile:
        json.dump(blocked_domains_lists, outfile, separators=(',', ':'), cls=EnhancedJSONEncoder)

    with open('isp-blocked-domains.json', 'w') as outfile:
        json.dump(blocked_domains_lists, outfile, indent=4, cls=EnhancedJSONEncoder)


if __name__ == '__main__':
    write_blocked_domain_files()
