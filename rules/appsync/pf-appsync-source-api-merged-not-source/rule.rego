package cdk_preflight

import rego.v1

# Judged only when the source API is a sibling resource, so its ApiType is
# visible in this template.
violation contains make_diag_full("pf-appsync-source-api-merged-not-source", "ERROR", name,
	"Properties.SourceApiIdentifier",
	sprintf("source API '%s' is itself a MERGED API; the association create fails because a merged API cannot be merged into another one", [src]),
	"Point SourceApiIdentifier at an ApiType: GRAPHQL API",
	"https://docs.aws.amazon.com/appsync/latest/devguide/merged-api.html") if {
	some name in resources_of_type("AWS::AppSync::SourceApiAssociation")
	src := resolve(name, "Properties.SourceApiIdentifier")
	src in resources_of_type("AWS::AppSync::GraphQLApi")
	resolve(src, "Properties.ApiType") == "MERGED"
}
