package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ec2-launch-template-name", "ERROR", name,
	"Properties.LaunchTemplateName",
	sprintf("LaunchTemplateName '%s' is rejected: EC2 requires 3-128 characters of letters, numbers and - ( ) . / _", [n]),
	"Rename the launch template using only letters, numbers and - ( ) . / _ (3-128 characters)",
	"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateLaunchTemplate.html") if {
	some name in resources_of_type("AWS::EC2::LaunchTemplate")
	n := resolve(name, "Properties.LaunchTemplateName")
	is_string(n)
	not regex.match(`^[a-zA-Z0-9()./_-]{3,128}$`, n)
}
