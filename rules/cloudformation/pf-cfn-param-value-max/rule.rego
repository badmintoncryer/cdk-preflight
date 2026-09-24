package cdk_preflight

import rego.v1

# 4096 characters, measured on the Default the template ships. count() counts
# code points; the service counts bytes, so a non-ASCII default is undercounted
# here on purpose (under-detecting beats guessing at an encoding).
_pf_cfnpvmax_bad contains [p, n] if {
	some p, spec in input.parameters
	d := object.get(spec, "default", null)
	is_string(d)
	n := count(d)
	n > 4096
}

violation contains make_diag_full("pf-cfn-param-value-max", "ERROR", p,
	sprintf("Parameters.%s.Default", [p]),
	sprintf("This parameter's default value is %d characters; CreateStack rejects the template with \"Parameter '%s' default value '...' length is greater than 4096.\"", [n, p]),
	"Keep parameter values at 4096 characters or fewer - pass larger payloads through S3 or SSM instead",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-limits.html") if {
	some [p, n] in _pf_cfnpvmax_bad
}
