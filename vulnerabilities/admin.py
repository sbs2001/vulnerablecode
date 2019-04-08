from base.admin import BaseAdmin

from django.contrib import admin

from vulnerabilities.models import (
    ImpactedPackage,
    Package,
    PackageReference,
    ResolvedPackage,
    Vulnerability,
    VulnerabilityReference
)


@admin.register(Vulnerability)
class VulnerabilityAdmin(BaseAdmin):
    pass


@admin.register(VulnerabilityReference)
class VulnerabilityReferenceAdmin(BaseAdmin):

    list_display = ('vulnerability', 'source', 'reference_id', 'url')
    readonly_fields = ('vulnerability',)


@admin.register(Package)
class PackageAdmin(BaseAdmin):
    pass


@admin.register(ImpactedPackage)
class ImpactedPackageAdmin(BaseAdmin):
    pass


@admin.register(ResolvedPackage)
class ResolvedPackageAdmin(BaseAdmin):
    pass


@admin.register(PackageReference)
class PackageReferenceAdmin(BaseAdmin):
    pass
