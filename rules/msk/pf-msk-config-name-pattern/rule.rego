package cdk_preflight

import rego.v1

# Name must match ^[0-9A-Za-z][0-9A-Za-z-]{0,}$ -- no underscores, dots or leading hyphen. The
# engine's schema carries no pattern for this property, and CreateConfiguration answers with a
# message that does not repeat the pattern ("The parameter value contains one or more characters
# that are not valid. ... InvalidParameter: name").
violation contains make_diag_full("pf-msk-config-name-pattern", "ERROR", name,
	"Properties.Name",
	sprintf("configuration name '%s' is not alphanumeric-with-hyphens; the create fails with \"The parameter value contains one or more characters that are not valid\"", [n]),
	"Use only A-Z, a-z and 0-9, plus hyphens after the first character",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-configuration.html") if {
	some name in resources_of_type("AWS::MSK::Configuration")
	n := resolve(name, "Properties.Name")
	is_string(n)
	not regex.match(`^[0-9A-Za-z][0-9A-Za-z-]*$`, n)
}
