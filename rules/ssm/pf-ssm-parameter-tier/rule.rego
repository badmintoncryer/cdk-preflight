package cdk_preflight

import rego.v1

_pf_ssmpt_url := "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html"

_pf_ssmpt_fix := "Set Tier: Advanced (or Intelligent-Tiering) for values over 4 KB and for parameter policies, and keep values under 8 KB"

_pf_ssmpt_tier(name) := t if {
	t := resolve(name, "Properties.Tier")
	is_string(t)
}

_pf_ssmpt_tier(name) := "Standard (account default)" if {
	object.get(input.resources[name].properties, "Tier", "__pf_absent") == "__pf_absent"
}

_pf_ssmpt_standard(t) if startswith(t, "Standard")

_pf_ssmpt_value(name) := v if {
	v := resolve(name, "Properties.Value")
	is_string(v)
}

violation contains make_diag_full("pf-ssm-parameter-tier", "ERROR", name,
	"Properties.Value",
	sprintf("Value is %d characters but tier %s allows 4096; PutParameter fails with \"Standard tier parameters support a maximum parameter value of 4096 characters.\"", [count(v), t]),
	_pf_ssmpt_fix, _pf_ssmpt_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	t := _pf_ssmpt_tier(name)
	_pf_ssmpt_standard(t)
	v := _pf_ssmpt_value(name)
	count(v) > 4096
}

violation contains make_diag_full("pf-ssm-parameter-tier", "ERROR", name,
	"Properties.Value",
	sprintf("Value is %d characters but tier %s allows 8192; PutParameter fails with \"Advanced-tier parameters support a maximum parameter value of 8192 characters.\"", [count(v), t]),
	_pf_ssmpt_fix, _pf_ssmpt_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	t := _pf_ssmpt_tier(name)
	not _pf_ssmpt_standard(t)
	v := _pf_ssmpt_value(name)
	count(v) > 8192
}

violation contains make_diag_full("pf-ssm-parameter-tier", "ERROR", name,
	"Properties.Policies",
	sprintf("parameter policies need the advanced tier but Tier is %s; PutParameter fails with \"You can't assign parameter policies to a standard-parameter tier.\"", [t]),
	_pf_ssmpt_fix, _pf_ssmpt_url) if {
	some name in resources_of_type("AWS::SSM::Parameter")
	t := _pf_ssmpt_tier(name)
	_pf_ssmpt_standard(t)
	object.get(input.resources[name].properties, "Policies", "__pf_absent") != "__pf_absent"
}
