package cdk_preflight

import rego.v1

# The 1024-byte ceiling applies to exported outputs only; a non-exported output
# of the same size is fine. count() counts code points, which is bytes for the
# ASCII values this can see resolved.
_pf_cfnevmax_bad contains [out, n] if {
	some out, o in input.outputs
	object.get(o, "exportName", null) != null
	v := object.get(o, "value", null)
	is_string(v)
	n := count(v)
	n > 1024
}

violation contains make_diag_full("pf-cfn-export-value-max", "ERROR", out,
	sprintf("Outputs.%s.Value", [out]),
	sprintf("This exported output value is %d bytes; CloudFormation fails the stack with \"Cannot export output %s with length %d. Max length of 1024 exceeded.\"", [n, out, n]),
	"Keep exported values at 1024 bytes or fewer, or drop the Export and read the output another way",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-exports.html") if {
	some [out, n] in _pf_cfnevmax_bad
}
