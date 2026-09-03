package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ec2-sg-group-name", "ERROR", name,
	"Properties.GroupName",
	sprintf("GroupName '%s' starts with the reserved prefix; EC2 rejects it with \"Group names may not be in the format sg-*\"", [gn]),
	"Pick a name that does not start with sg-",
	"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSecurityGroup.html") if {
	some name in resources_of_type("AWS::EC2::SecurityGroup")
	gn := resolve(name, "Properties.GroupName")
	is_string(gn)
	startswith(gn, "sg-")
}
