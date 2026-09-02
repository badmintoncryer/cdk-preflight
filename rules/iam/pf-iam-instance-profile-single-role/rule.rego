package cdk_preflight

import rego.v1

# The "quota" is a hard limit of one role; the schema has no maxItems.
violation contains make_diag_full("pf-iam-instance-profile-single-role", "ERROR", name,
	"Properties.Roles",
	sprintf("%d roles on one instance profile; the create fails with \"Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1\"", [n]),
	"Keep exactly one role per instance profile",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-instanceprofile.html") if {
	some name in resources_of_type("AWS::IAM::InstanceProfile")
	n := count(flatten_list(name, "Properties.Roles"))
	n > 1
}
