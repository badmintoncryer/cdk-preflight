package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-slr-service-name-format", "ERROR", name,
	"Properties.AWSServiceName",
	sprintf("AWSServiceName '%s' is not a service principal; the create fails with \"%s is not a valid AWS service name (Service Principal)\"", [v, v]),
	"Use the full service principal (elasticloadbalancing.amazonaws.com, ecs.amazonaws.com), not the service short name",
	"https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateServiceLinkedRole.html") if {
	some name in resources_of_type("AWS::IAM::ServiceLinkedRole")
	v := resolve(name, "Properties.AWSServiceName")
	is_string(v)
	not endswith(v, ".amazonaws.com")
}
