import graphene

import vulnerabilities.graphql_schema


class Query(vulnerabilities.graphql_schema.Query, graphene.ObjectType):
    # Top level Query class, not needed if we don't intend to have
    # other apps excluding 'vulnerabilities'
    pass


schema = graphene.Schema(query=Query)
