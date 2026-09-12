package cdk_preflight

import rego.v1

# The engine knows this allowed-value list but reports it as W3030 (WARN),
# which never blocks a deploy; see AGENTS.md on the gray zone.
violation contains make_diag_full("pf-appsync-source-api-merge-type-value", "ERROR", name,
	"Properties.SourceApiAssociationConfig.MergeType",
	sprintf("MergeType '%s' is not AUTO_MERGE or MANUAL_MERGE; the association create rejects the value", [v]),
	"Use AUTO_MERGE or MANUAL_MERGE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appsync-sourceapiassociation-sourceapiassociationconfig.html") if {
	some name in resources_of_type("AWS::AppSync::SourceApiAssociation")
	v := resolve(name, "Properties.SourceApiAssociationConfig.MergeType")
	is_string(v)
	not v in {"AUTO_MERGE", "MANUAL_MERGE"}
}
