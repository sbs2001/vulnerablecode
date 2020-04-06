import graphene
from graphene_django.types import DjangoObjectType
from graphene_django.filter import DjangoFilterConnectionField

from vulnerabilities.models import Vulnerability, Package


class VulnerabilityType(DjangoObjectType):
    class Meta:
        model = Vulnerability
        interfaces = (graphene.Node,)
        filter_fields = ["cve_id"]


class PackageType(DjangoObjectType):
    purl = graphene.String(source='package_url')
    # TODO: implement is_vulnerable resolver
    # is_vulnerable = graphene.Boolean()

    class Meta:
        model = Package
        interfaces = (graphene.Node,)
        filter_fields = ["version", "name", "type"]


class Query(object):
    all_packages = DjangoFilterConnectionField(PackageType)
    all_vulnerabilities = DjangoFilterConnectionField(VulnerabilityType)
