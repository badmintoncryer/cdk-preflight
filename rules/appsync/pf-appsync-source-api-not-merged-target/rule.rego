package cdk_preflight

import rego.v1

# Judged only when the target API is a sibling resource, so its ApiType is
# visible in this template.
_pf_sourceapinotmergedtarget_merged(n) if resolve(n, "Properties.ApiType") == "MERGED"

violation contains make_diag_full("pf-appsync-source-api-not-merged-target", "ERROR", name,
	"Properties.MergedApiIdentifier",
	sprintf("API '%s' is not an ApiType: MERGED API; the association create fails because source APIs can only be associated with a merged API", [m]),
	"Set ApiType: MERGED on the target API, or point MergedApiIdentifier at one",
	"https://docs.aws.amazon.com/appsync/latest/devguide/merged-api.html") if {
	some name in resources_of_type("AWS::AppSync::SourceApiAssociation")
	m := resolve(name, "Properties.MergedApiIdentifier")
	m in resources_of_type("AWS::AppSync::GraphQLApi")
	not _pf_sourceapinotmergedtarget_merged(m)
}
