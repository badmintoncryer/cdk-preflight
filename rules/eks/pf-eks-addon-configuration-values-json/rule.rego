package cdk_preflight

import rego.v1

# ConfigurationValues accepts YAML as well as JSON, so only a string that opens
# as a serialised JSON object ({") is checked: an unclosed flow mapping is
# invalid in both grammars, while YAML flow style like {replicaCount: 1} is not.
violation contains make_diag_full("pf-eks-addon-configuration-values-json", "ERROR", name,
	"Properties.ConfigurationValues",
	"ConfigurationValues opens a JSON object but does not parse (\"The ConfigurationValues provided is not in valid YAML or JSON format.\")",
	"Render the configuration with JSON.stringify / Fn::ToJsonString instead of hand-written JSON",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-addon.html") if {
	some name in resources_of_type("AWS::EKS::Addon")
	s := resolve(name, "Properties.ConfigurationValues")
	is_string(s)
	startswith(s, "{\"")
	not json.is_valid(s)
}
