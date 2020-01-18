import os
import urllib.request
from itertools import chain
from shutil import rmtree
from urllib.error import HTTPError
from zipfile import ZipFile

import saneyaml
from dephell_specifier import RangeSpecifier

RUBYCVE_LINK = 'https://github.com/rubysec/ruby-advisory-db/archive/master.zip'
DOWNLOAD_PATH = os.path.dirname(os.path.realpath(__file__))


def get_rubycve_db():
    path_to_zip, _ = urllib.request.urlretrieve(
        RUBYCVE_LINK, os.path.join(
            DOWNLOAD_PATH, 'ruby.zip'))
    ZipFile(path_to_zip).extractall(DOWNLOAD_PATH)
    os.remove(path_to_zip)


def path_of_yaml_of_all_packages():
    gem_path = os.path.join(DOWNLOAD_PATH, 'ruby-advisory-db-master', 'gems')
    rubies_path = os.path.join(
        DOWNLOAD_PATH,
        'ruby-advisory-db-master',
        'rubies')
    for (
            package_path,
            _,
            yaml_names) in chain(
            os.walk(gem_path),
            os.walk(rubies_path)):
        for yaml_name in yaml_names:
            yield os.path.join(package_path, yaml_name)


def get_all_versions_of_package(package_name):
    url_to_load = 'https://rubygems.org/api/v1/versions/' + package_name + '.yaml'
    try:
        page = urllib.request.urlopen(url_to_load)
        package_history = saneyaml.load(page)
    except HTTPError:
        return []
    for version in package_history:
        yield version['number']


def get_patched_range(spec_list):
    if spec_list:
        def remove_space(string): return string.replace(' ', '')
        spec_list = list(map(remove_space, spec_list))
        for spec in spec_list:
            if 'rc' in spec:
                continue
            yield RangeSpecifier(spec)
    else:
        return None


def import_vulnerabilities():
    get_rubycve_db()
    ids = set()
    vulnerability_to_package_map = []
    for vulnerability_path in path_of_yaml_of_all_packages():
        with open(vulnerability_path) as yaml_file:
            vulnerability = saneyaml.load(yaml_file)
            package_name = vulnerability.get(
                'engine', vulnerability.get('gem'))
            summary = vulnerability.get('description', '')
            if 'cve' in vulnerability:
                vulnerability_id = 'CVE-{}'.format(vulnerability['cve'])
                if vulnerability_id in ids:
                    continue
                ids.add(vulnerability_id)
            else:
                continue
            severity = vulnerability.get(
                'cvss_v3', vulnerability.get('cvss_v2'))
            advisory_url = vulnerability.get('url')
            specs = list(
                get_patched_range(
                    vulnerability.get('patched_versions')))
            all_versions = set(list(get_all_versions_of_package(package_name)))
            unaffected_versions = set()
            if specs:
                for version in all_versions:
                    for spec in specs:
                        if version in spec:
                            unaffected_versions.add(version)
                            break
            affected_versions = all_versions - unaffected_versions
            vulnerability_to_package_map.append({
                'package_name': package_name,
                'summary': summary,
                'cve_id': vulnerability_id,
                'fixed_versions': unaffected_versions,
                'affected_versions': affected_versions,
                'severity': severity,
                'advisory': advisory_url
            })
    rmtree(os.path.join(DOWNLOAD_PATH, 'ruby-advisory-db-master'))
    return vulnerability_to_package_map
