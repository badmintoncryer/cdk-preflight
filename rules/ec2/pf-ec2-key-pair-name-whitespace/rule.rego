package cdk_preflight

import rego.v1

_pf_ec2kpn_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-keypair.html"

violation contains make_diag_full("pf-ec2-key-pair-name-whitespace", "ERROR", name,
	"Properties.KeyName",
	sprintf("KeyName '%s' has leading or trailing whitespace (\"Invalid value '%s' for keyName. It should be trimmed\")", [n, n]),
	"Trim the key pair name",
	_pf_ec2kpn_url) if {
	some name in resources_of_type("AWS::EC2::KeyPair")
	n := resolve(name, "Properties.KeyName")
	is_string(n)
	trim_space(n) != n
}
