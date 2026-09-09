package cdk_preflight

import rego.v1

# The constraints are typed as strings, so no schema layer compares them.

violation contains make_diag_full("pf-cognito-schema-number-min-max-order", "ERROR", name,
	sprintf("Properties.Schema.%d.NumberAttributeConstraints", [a.index]),
	sprintf("attribute '%s' has MinValue %v over MaxValue %v; the pool create fails with \"Attribute custom:%s cannot have a max value smaller than it's min value\"", [n, mn, mx, n]),
	"Keep MinValue less than or equal to MaxValue",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.Schema")
	is_object(a.value)
	n := object.get(a.value, "Name", "")
	nac := _pf_coglib_at(a.value, "NumberAttributeConstraints")
	is_object(nac)
	mn_raw := object.get(nac, "MinValue", "__pf_absent")
	mn_raw != "__pf_absent"
	mx_raw := object.get(nac, "MaxValue", "__pf_absent")
	mx_raw != "__pf_absent"
	mn := to_number(mn_raw)
	mx := to_number(mx_raw)
	mn > mx
}
