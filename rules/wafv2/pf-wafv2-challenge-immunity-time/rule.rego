package cdk_preflight

import rego.v1

_pf_wafcit_url := "https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-immunity-times.html"

_pf_wafcit_fix := "Set ChallengeConfig.ImmunityTimeProperty.ImmunityTime to 300 or more (only CaptchaConfig goes down to 60)"

_pf_wafcit_msg(t) := sprintf("challenge immunity time %d is below the minimum of 300 seconds (the CAPTCHA minimum of 60 in the schema does not apply); the create call fails with \"The parameter value is out of bounds.\"", [t])

violation contains make_diag_full("pf-wafv2-challenge-immunity-time", "ERROR", name, "Properties.ChallengeConfig.ImmunityTimeProperty.ImmunityTime",
	_pf_wafcit_msg(t), _pf_wafcit_fix, _pf_wafcit_url) if {
	some name in _pf_waflib_containers
	t := resolve(name, "Properties.ChallengeConfig.ImmunityTimeProperty.ImmunityTime")
	is_number(t)
	t < 300
}

violation contains make_diag_full("pf-wafv2-challenge-immunity-time", "ERROR", name, sprintf("Properties.Rules[%d].ChallengeConfig.ImmunityTimeProperty.ImmunityTime", [i]),
	_pf_wafcit_msg(t), _pf_wafcit_fix, _pf_wafcit_url) if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i
	t := rules[i].ChallengeConfig.ImmunityTimeProperty.ImmunityTime
	is_number(t)
	t < 300
}
