package cdk_preflight

import rego.v1

_pf_ssmpn_url := "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html"

_pf_ssmpn_fix := "Rename the parameter: hierarchical segments of letters, digits, _ . -, no aws/ssm prefix, and short enough that arn:<partition>:ssm:<region>:<account>:parameter/<name> is at most 1011 characters"

_pf_ssmpn_name(name) := n if {
	n := resolve(name, "Properties.Name")
	is_string(n)
}

_pf_ssmpn_bare(n) := trim_prefix(n, "/")

violation contains make_diag_full("pf-ssm-parameter-name", "ERROR", name,
	"Properties.Name",
	sprintf("'%s' starts with the reserved prefix '%s' (case-insensitive); PutParameter fails with \"Parameter name: can't be prefixed with \\\"aws\\\" or \\\"ssm\\\" (case-insensitive).\"", [n, pfx]),
	_pf_ssmpn_fix, _pf_ssmpn_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	n := _pf_ssmpn_name(name)
	some pfx in ["aws", "ssm"]
	startswith(lower(_pf_ssmpn_bare(n)), pfx)
}

violation contains make_diag_full("pf-ssm-parameter-name", "ERROR", name,
	"Properties.Name",
	sprintf("'%s' ends with a slash; PutParameter fails with \"Parameter name must not end with slash.\"", [n]),
	_pf_ssmpn_fix, _pf_ssmpn_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	n := _pf_ssmpn_name(name)
	endswith(n, "/")
}

violation contains make_diag_full("pf-ssm-parameter-name", "ERROR", name,
	"Properties.Name",
	sprintf("segment '%s' of '%s' is not made of letters, digits, _ . - only (empty segments are not allowed either); PutParameter rejects the name", [seg, n]),
	_pf_ssmpn_fix, _pf_ssmpn_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	n := _pf_ssmpn_name(name)
	not endswith(n, "/")
	some seg in split(_pf_ssmpn_bare(n), "/")
	not regex.match("^[A-Za-z0-9_.-]+$", seg)
}

# The ARN prefix arn:<partition>:ssm:<region>:<account>:parameter/ counts towards the 1011-character
# limit, so the allowed name length depends on the deploy region (data.cdk_preflight.deploy_region).
violation contains make_diag_full("pf-ssm-parameter-name", "ERROR", name,
	"Properties.Name",
	sprintf("the name is %d characters, but with the %d-character ARN prefix for %s only %d fit into the 1011-character limit; PutParameter fails with AccessDeniedException on the oversized ARN", [count(bare), prefix, region, 1011 - prefix]),
	_pf_ssmpn_fix, _pf_ssmpn_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::SSM::Parameter")
	bare := _pf_ssmpn_bare(_pf_ssmpn_name(name))
	prefix := 36 + count(region)
	count(bare) + prefix > 1011
}
