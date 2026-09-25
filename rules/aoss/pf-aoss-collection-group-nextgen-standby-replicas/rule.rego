package cdk_preflight

import rego.v1

# StandbyReplicas is Required: Yes with both values allowed and Generation is a
# free-standing enum; nothing in the schema ties them together. NEXTGEN accepts
# only ENABLED.

violation contains make_diag_full("pf-aoss-collection-group-nextgen-standby-replicas", "ERROR", name,
	"Properties.StandbyReplicas",
	"Generation is NEXTGEN but StandbyReplicas is DISABLED; CreateCollectionGroup answers \"StandbyReplicas cannot be set to DISABLED for NEXTGEN collection groups.\"",
	"Set StandbyReplicas to ENABLED, or leave Generation at CLASSIC",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchserverless-collectiongroup.html") if {
	some name in resources_of_type("AWS::OpenSearchServerless::CollectionGroup")
	resolve(name, "Properties.Generation") == "NEXTGEN"
	resolve(name, "Properties.StandbyReplicas") == "DISABLED"
}
