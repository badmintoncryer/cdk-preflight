package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region is defined only when the enforce plugin
# knows the app's concrete region (see src/private/enforce.ts); without it the
# reference is undefined and this rule skips. Replicas with unresolvable
# Region values also make the rule skip — absence cannot be proven then.
violation contains make_diag_full("pf-dynamodb-global-table-replica-region", "ERROR", name,
	"Properties.Replicas",
	sprintf("The Replicas list %v does not include the deployment region '%s'; CreateGlobalTable fails with \"The Replicas section must contain an entry for the current region\"", [replicas, region]),
	"Add a replica entry for the region the stack deploys to (CDK TableV2 does this automatically)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-globaltable.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	items := [it | some it in flatten_list(name, "Properties.Replicas")]
	count(items) > 0
	every it in items {
		is_string(object.get(it.value, "Region", null))
	}
	replicas := [r | some it in items; r := object.get(it.value, "Region", null)]
	not region in replicas
}
