from dephell_specifier import RangeSpecifier

from vulnerabilities.scraper.ruby import get_all_versions_of_package
from vulnerabilities.scraper.ruby import get_patched_range


def test_get_all_versions_of_package():
    versions = set(get_all_versions_of_package('actionpack'))
    expected = set(['1.10.2', '4.0.3', '3.2.3', '4.2.0.beta3',
                    '5.2.3', '4.1.14.2', '4.0.13'])
    assert versions >= expected


def test_get_patched_range():
    expected = set([RangeSpecifier('>4'), RangeSpecifier('~>4.1')])
    assert set(get_patched_range(['>4', '~>4.1', '>4.2rc'])) == expected
