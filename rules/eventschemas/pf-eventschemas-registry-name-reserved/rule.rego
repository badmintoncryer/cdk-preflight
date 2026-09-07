package cdk_preflight

import rego.v1

# "You do not have the permission to create/modify an AWS managed registry
# with name prefixed with 'aws.'." Measured 2026-09-07, schemas:CreateRegistry,
# us-east-1.
violation contains make_diag_full("pf-eventschemas-registry-name-reserved", "ERROR", name,
	"Properties.RegistryName",
	sprintf("'%s' uses the aws. prefix, which is reserved for AWS-managed registries; CreateRegistry fails with \"You do not have the permission to create/modify an AWS managed registry with name prefixed with 'aws.'\"", [n]),
	"Choose a registry name that does not start with 'aws.'",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eventschemas-registry.html") if {
	some name in resources_of_type("AWS::EventSchemas::Registry")
	n := resolve(name, "Properties.RegistryName")
	is_string(n)
	startswith(n, "aws.")
}
