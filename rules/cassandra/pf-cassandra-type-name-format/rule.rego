package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-type-name-format", "ERROR", name, "Properties.TypeName",
	sprintf("TypeName %v must start with a letter and contain only letters, digits and underscores (or be double-quoted); Keyspaces answers \"contains invalid characters\"", [n]),
	"Rename the type, e.g. my_addr",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cassandra-type.html#cfn-cassandra-type-typename") if {
	some name in resources_of_type("AWS::Cassandra::Type")
	n := object.get(input.resources[name].properties, "TypeName", null)
	is_string(n)
	not regex.match(`^".+"$`, n)
	not regex.match(`^[A-Za-z][A-Za-z0-9_]*$`, n)
}
