package cdk_preflight

import rego.v1

_pf_ecua_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateUser.html"

_pf_ecua_fix := "Set NoPasswordRequired: true, or give the user one or two passwords of 16-128 characters (or AuthenticationMode with Type iam)"

_pf_ecua_passwords(name) := p if {
	p := resolve(name, "Properties.Passwords")
	is_array(p)
}

_pf_ecua_authmode(name) := m if {
	m := object.get(input.resources[name].properties, "AuthenticationMode", null)
	is_object(m)
}

violation contains make_diag_full("pf-elasticache-user-authentication", "ERROR", name,
	"Properties.Passwords",
	"Passwords are set together with NoPasswordRequired; the create call fails with \"Password field is not allowed with authentication type: no-password-required\"",
	_pf_ecua_fix, _pf_ecua_url) if {
	some name in resources_of_type("AWS::ElastiCache::User")
	resolve(name, "Properties.NoPasswordRequired") == true
	count(_pf_ecua_passwords(name)) > 0
}

violation contains make_diag_full("pf-elasticache-user-authentication", "ERROR", name,
	"Properties.Passwords",
	sprintf("a password is %d characters; the create call fails with \"Passwords length must be between 16-128 characters.\"", [count(p)]),
	_pf_ecua_fix, _pf_ecua_url) if {
	some name in resources_of_type("AWS::ElastiCache::User")
	some p in _pf_ecua_passwords(name)
	_pf_cachelib_lit(p)
	_pf_ecua_bad_length(count(p))
}

_pf_ecua_bad_length(n) if n < 16

_pf_ecua_bad_length(n) if n > 128

violation contains make_diag_full("pf-elasticache-user-authentication", "ERROR", name,
	"Properties.Passwords",
	sprintf("%d passwords are set; the create call fails with \"Maximum number of passwords allowed in this service is 2.\"", [count(ps)]),
	_pf_ecua_fix, _pf_ecua_url) if {
	some name in resources_of_type("AWS::ElastiCache::User")
	ps := _pf_ecua_passwords(name)
	count(ps) > 2
}

# Neither Passwords, NoPasswordRequired nor AuthenticationMode leaves the user
# without an authentication type at all.
violation contains make_diag_full("pf-elasticache-user-authentication", "ERROR", name,
	"Properties.AuthenticationMode",
	"the user sets no authentication mode; the create call fails with \"Input Authentication type: null is not in the allowed list: [password,no-password-required,iam]\"",
	_pf_ecua_fix, _pf_ecua_url) if {
	some name in resources_of_type("AWS::ElastiCache::User")
	_pf_cachelib_absent(name, "AuthenticationMode")
	_pf_cachelib_absent(name, "NoPasswordRequired")
	_pf_cachelib_absent(name, "Passwords")
}
