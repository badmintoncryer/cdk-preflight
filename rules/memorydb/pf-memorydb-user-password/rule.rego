package cdk_preflight

import rego.v1

_pf_mdbup_url := "https://docs.aws.amazon.com/memorydb/latest/APIReference/API_CreateUser.html"

_pf_mdbup_fix := "Give AuthenticationMode Type password one or two passwords of 16-128 characters, or use Type iam"

_pf_mdbup_mode(name) := m if {
	m := object.get(input.resources[name].properties, "AuthenticationMode", null)
	is_object(m)
}

_pf_mdbup_passwords(name) := ps if {
	ps := object.get(_pf_mdbup_mode(name), "Passwords", null)
	is_array(ps)
}

violation contains make_diag_full("pf-memorydb-user-password", "ERROR", name,
	"Properties.AuthenticationMode.Passwords",
	sprintf("a password is %d characters; CreateUser fails with \"Passwords length must be between 16-128 characters.\"", [count(p)]),
	_pf_mdbup_fix, _pf_mdbup_url) if {
	some name in resources_of_type("AWS::MemoryDB::User")
	some p in _pf_mdbup_passwords(name)
	_pf_cachelib_lit(p)
	_pf_mdbup_bad_length(count(p))
}

_pf_mdbup_bad_length(n) if n < 16

_pf_mdbup_bad_length(n) if n > 128

violation contains make_diag_full("pf-memorydb-user-password", "ERROR", name,
	"Properties.AuthenticationMode",
	"AuthenticationMode Type is password but no Passwords are given; CreateUser needs at least one password of 16-128 characters",
	_pf_mdbup_fix, _pf_mdbup_url) if {
	some name in resources_of_type("AWS::MemoryDB::User")
	mode := _pf_mdbup_mode(name)
	lower(object.get(mode, "Type", "")) == "password"
	count(object.get(mode, "Passwords", [])) == 0
}
