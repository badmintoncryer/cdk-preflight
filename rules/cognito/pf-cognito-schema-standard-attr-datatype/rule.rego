package cdk_preflight

import rego.v1

# The schema entry may re-declare a standard attribute (to make it required or
# immutable) but not retype it; the type table is service knowledge.

violation contains make_diag_full("pf-cognito-schema-standard-attr-datatype", "ERROR", name,
	sprintf("Properties.Schema.%d.AttributeDataType", [a.index]),
	sprintf("standard attribute '%s' is declared as %s, but its type is fixed to %s; the pool create fails with \"You can not change AttributeDataType or set developerOnlyAttribute for standard schema attribute %s\"", [n, dt, want, n]),
	"Declare the standard attribute with its own data type, or use a custom attribute",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.Schema")
	is_object(a.value)
	n := object.get(a.value, "Name", "")
	want := _pf_coglib_std_attr_types[n]
	dt := _pf_coglib_at(a.value, "AttributeDataType")
	is_string(dt)
	dt != want
}
