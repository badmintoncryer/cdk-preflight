package cdk_preflight

import rego.v1

# Both properties are optional in the schema, so the "exactly one" rule only
# exists in the StackSets API.
_pf_cfnssacct_bad contains [name, idx] if {
	some name in resources_of_type("AWS::CloudFormation::StackSet")
	some g in flatten_list(name, "Properties.StackInstancesGroup")
	dt := object.get(g.value, "DeploymentTargets", {})
	object.get(dt, "Accounts", null) != null
	object.get(dt, "AccountsUrl", null) != null
	idx := g.index
}

violation contains make_diag_full("pf-cfn-stackset-accounts-exclusive", "ERROR", name,
	sprintf("Properties.StackInstancesGroup.%d.DeploymentTargets", [idx]),
	"This deployment target sets both Accounts and AccountsUrl; CloudFormation fails the stack set with \"Exactly one of Accounts or AccountsURL must be specified\"",
	"Keep either Accounts or AccountsUrl and delete the other",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudformation-stackset-deploymenttargets.html") if {
	some [name, idx] in _pf_cfnssacct_bad
}
