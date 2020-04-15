#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import Package
from vulnerabilities.models import PackageReference
from vulnerabilities.models import ResolvedPackage
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference


def debian_dump(extract_data, base_release="jessie"):
    """
    Save data scraped from Debian' security tracker.
    """
    for data in extract_data:
        vulnerability, _ = Vulnerability.objects.get_or_create(cve_id=data["cve_id"],)

        pkg_name = data["package_name"]
        package = Package.objects.create(
            name=pkg_name,
            type="deb",
            namespace="debian",
            version=data.get("version", ""),
            qualifiers=f"distro={base_release}",
        )

        if data["status"] == "open":
            ImpactedPackage.objects.create(vulnerability=vulnerability, package=package)
        else:
            ResolvedPackage.objects.create(vulnerability=vulnerability, package=package)

            fixed_version = data.get("fixed_version")
            if fixed_version:
                package = Package.objects.create(
                    name=pkg_name,
                    type="deb",
                    namespace="debian",
                    version=fixed_version,
                    qualifiers=f"distro={base_release}",
                )

                ResolvedPackage.objects.create(vulnerability=vulnerability, package=package)


def ubuntu_dump(html):
    """
    Dump data scraped from Ubuntu's security tracker.
    """
    for data in html:
        vulnerability, _ = Vulnerability.objects.get_or_create(cve_id=data["cve_id"],)
        package = Package.objects.create(name=data["package_name"], type="deb", namespace="ubuntu")
        ImpactedPackage.objects.create(vulnerability=vulnerability, package=package)


def archlinux_dump(extract_data):
    """
    Save data scraped from archlinux' security tracker.
    """
    base_url = "https://security.archlinux.org"

    for avg in extract_data:
        affected_packages = []
        fixed_packages = []

        for package_name in avg["packages"]:
            ap, _ = Package.objects.get_or_create(
                name=package_name, type="pacman", namespace="archlinux", version=avg["affected"],
            )
            affected_packages.append(ap)

            fp, _ = Package.objects.get_or_create(
                name=package_name, type="pacman", namespace="archlinux", version=avg["fixed"],
            )
            fixed_packages.append(fp)

        for cve_id in avg["issues"]:
            vulnerability, _ = Vulnerability.objects.get_or_create(cve_id=cve_id,)
            VulnerabilityReference.objects.create(
                vulnerability=vulnerability, url=f"{base_url}/{cve_id}",
            )
            avg_name = avg["name"]
            VulnerabilityReference.objects.create(
                vulnerability=vulnerability, reference_id=avg_name, url=f"{base_url}/{avg_name}",
            )

            for asa in avg["advisories"]:
                VulnerabilityReference.objects.create(
                    vulnerability=vulnerability, reference_id=asa, url=f"{base_url}/{asa}",
                )

            for ap in affected_packages:
                ImpactedPackage.objects.get_or_create(
                    vulnerability=vulnerability, package=ap,
                )

            for fp in fixed_packages:
                ResolvedPackage.objects.get_or_create(
                    vulnerability=vulnerability, package=fp,
                )


def npm_dump(extract_data):
    for data in extract_data:
        package_name = data["package_name"]
        advisory = data["advisory"]

        for cve_id in data["cve_ids"]:
            vulnerability, _ = Vulnerability.objects.get_or_create(cve_id=cve_id,)

            if advisory:
                VulnerabilityReference.objects.create(
                    vulnerability=vulnerability, url=advisory,
                )

            for version in data["affected_versions"]:
                package_affected = Package.objects.create(
                    name=package_name, type="npm", version=version,
                )
                ImpactedPackage.objects.create(
                    vulnerability=vulnerability, package=package_affected
                )

            for version in data["fixed_versions"]:
                package_fixed = Package.objects.create(
                    name=package_name, type="npm", version=version
                )
                ResolvedPackage.objects.create(vulnerability=vulnerability, package=package_fixed)


def ruby_dump(extract_data):
    for package_data in extract_data:

        vulnerability, _ = Vulnerability.objects.get_or_create(cve_id=package_data["cve_id"])

        VulnerabilityReference.objects.get_or_create(
            vulnerability=vulnerability, url=package_data["advisory"]
        )

        for version in package_data["affected_versions"]:
            affected_package = Package.objects.create(
                name=package_data["package_name"], type="gem", version=version
            )
            ImpactedPackage.objects.create(vulnerability=vulnerability, package=affected_package)

        for version in package_data["fixed_versions"]:
            unaffected_package = Package.objects.create(
                name=package_data["package_name"], type="gem", version=version
            )
            ResolvedPackage.objects.create(vulnerability=vulnerability, package=unaffected_package)


def rust_dump(extract_data):

    for package_data in extract_data:

        vulnerability, _ = Vulnerability.objects.get_or_create(summary=package_data["description"])

        VulnerabilityReference.objects.get_or_create(
            vulnerability=vulnerability,
            url=package_data["advisory"],
            reference_id=package_data["vuln_id"],
        )

        for version in package_data["affected_versions"]:
            affected_package = Package.objects.create(
                name=package_data["package_name"], type="cargo", version=version
            )
            ImpactedPackage.objects.create(vulnerability=vulnerability, package=affected_package)

        for version in package_data["fixed_versions"]:
            unaffected_package = Package.objects.create(
                name=package_data["package_name"], type="cargo", version=version
            )
            ResolvedPackage.objects.create(vulnerability=vulnerability, package=unaffected_package)


def safetydb_dump(extract_data):
    for package_data in extract_data:
        for cve_id in package_data["cve_id"]:
            vulnerability, _ = Vulnerability.objects.get_or_create(
                summary=package_data["description"], cve_id=cve_id
            )

        VulnerabilityReference.objects.get_or_create(
            vulnerability=vulnerability, reference_id=package_data["vuln_id"]
        )

        for version in package_data["affected_versions"]:
            affected_package = Package.objects.create(
                name=package_data["package_name"], type="pypi", version=version
            )
            ImpactedPackage.objects.create(vulnerability=vulnerability, package=affected_package)

        for version in package_data["unaffected_versions"]:
            unaffected_package = Package.objects.create(
                name=package_data["package_name"], type="pypi", version=version
            )
            ResolvedPackage.objects.create(vulnerability=vulnerability, package=unaffected_package)


def alpine_linux_dump(data_dicts):
    for package_data in data_dicts:
        unaffected_package = Package.objects.create(
            name=package_data["package_name"], type="alpine", version=package_data["fixed_version"]
        )

        for vuln_groups in package_data["vuln_ids"]:
            if vuln_groups[0].startswith("CVE"):
                vulnerability_obj, _ = Vulnerability.objects.get_or_create(cve_id=vuln_groups[0])
                if len(vuln_groups) == 2:
                    # TODO: Deal with  vulnerabilities without cves
                    VulnerabilityReference.objects.get_or_create(
                        vulnerability=vulnerability_obj, reference_id=vuln_groups[1]
                    )

            else:

                continue

            ResolvedPackage.objects.create(
                vulnerability=vulnerability_obj, package=unaffected_package
            )


def opensuse_dump(extract_data):

    for package_data in extract_data:
        vulnerability, _ = Vulnerability.objects.get_or_create(cve_id=package_data["vuln_id"])
        for url in package_data["urls"]:
            for suse_id in package_data["ref_ids"]:
                # TODO: Enable  VulnerabilityReference to store multiple reference_id and
                # urls and remove these loops.
                VulnerabilityReference.objects.get_or_create(
                    vulnerability=vulnerability, url=package_data["urls"], reference_id=suse_id
                )
        # FIXME: Deal with duplicate package entries
        affected_package = Package.objects.create(
            name=package_data["package_name"],
            type="rpm",
            version=package_data["version"],
            namespace="opensuse",
        )
        # TODO: Add qualifiers of platform and distro once we start using
        # JSONField to store qualifiers.
        ImpactedPackage.objects.create(vulnerability=vulnerability, package=affected_package)
