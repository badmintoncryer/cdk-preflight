package cdk_preflight

import rego.v1

# The constraints are typed as strings, so no schema layer can compare
# them numerically.
violation contains make_diag_full("pf-cognito-schema-attr-length-order", "ERROR", name,
	sprintf("Properties.Schema.%d.StringAttributeConstraints", [att.index]),
	sprintf("Attribute '%s' has MinLength %v over MaxLength %v; the pool create fails with \"cannot have a max length shorter than it's min length\"", [object.get(att.value, "Name", "<attr>"), mn, mx]),
	"Keep MinLength less than or equal to MaxLength",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cognito-userpool-schemaattribute.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some att in flatten_list(name, "Properties.Schema")
	is_object(att.value)
	sac := object.get(att.value, "StringAttributeConstraints", {})
	is_object(sac)
	mn_raw := object.get(sac, "MinLength", "__pf_absent")
	mn_raw != "__pf_absent"
	mx_raw := object.get(sac, "MaxLength", "__pf_absent")
	mx_raw != "__pf_absent"
	mn := to_number(mn_raw)
	mx := to_number(mx_raw)
	mn > mx
}
