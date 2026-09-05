package cdk_preflight

import rego.v1

_pf_smgss_url := "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetRandomPassword.html"

_pf_smgss_fix := "Keep at least as many characters as required types (or set RequireEachIncludedType: false), do not exclude every type, and set SecretStringTemplate and GenerateStringKey together"

_pf_smgss_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

_pf_smgss_gen(name) := g if {
	g := object.get(_pf_smgss_props(name), "GenerateSecretString", null)
	is_object(g)
}

_pf_smgss_flag(g, k) if object.get(g, k, false) in {true, "true"}

_pf_smgss_types := ["ExcludeLowercase", "ExcludeUppercase", "ExcludeNumbers", "ExcludePunctuation"]

_pf_smgss_included(g) := 4 - count({k | some k in _pf_smgss_types; _pf_smgss_flag(g, k)})

_pf_smgss_require(g) if object.get(g, "RequireEachIncludedType", true) in {true, "true"}

_pf_smgss_len(g) := n if {
	n := object.get(g, "PasswordLength", 32)
	is_number(n)
}

_pf_smgss_len(g) := to_number(v) if {
	v := object.get(g, "PasswordLength", 32)
	is_string(v)
	regex.match("^[0-9]+$", v)
}

violation contains make_diag_full("pf-secretsmanager-generate-secret-string", "ERROR", name,
	"Properties.GenerateSecretString",
	"every character type is excluded (ExcludeLowercase, ExcludeUppercase, ExcludeNumbers and ExcludePunctuation are all true); GetRandomPassword fails with \"All characters have been excluded from selection.\"",
	_pf_smgss_fix, _pf_smgss_url) if {
	some name in resources_of_type("AWS::SecretsManager::Secret")
	g := _pf_smgss_gen(name)
	_pf_smgss_included(g) == 0
}

violation contains make_diag_full("pf-secretsmanager-generate-secret-string", "ERROR", name,
	"Properties.GenerateSecretString.PasswordLength",
	sprintf("PasswordLength %v is shorter than the %d character types that must each appear (RequireEachIncludedType defaults to true); GetRandomPassword fails with \"Password length is too short based on the required types.\"", [n, types]),
	_pf_smgss_fix, _pf_smgss_url) if {
	some name in resources_of_type("AWS::SecretsManager::Secret")
	g := _pf_smgss_gen(name)
	_pf_smgss_require(g)
	types := _pf_smgss_included(g)
	types > 0
	n := _pf_smgss_len(g)
	n >= 1
	n < types
}

violation contains make_diag_full("pf-secretsmanager-generate-secret-string", "ERROR", name,
	"Properties.GenerateSecretString.PasswordLength",
	sprintf("PasswordLength %v is outside 1..4096; GetRandomPassword rejects it", [n]),
	_pf_smgss_fix, _pf_smgss_url) if {
	some name in resources_of_type("AWS::SecretsManager::Secret")
	g := _pf_smgss_gen(name)
	n := _pf_smgss_len(g)
	_pf_smgss_out(n)
}

_pf_smgss_out(n) if n < 1

_pf_smgss_out(n) if n > 4096

violation contains make_diag_full("pf-secretsmanager-generate-secret-string", "ERROR", name,
	"Properties.GenerateSecretString.ExcludeCharacters",
	sprintf("ExcludeCharacters is %d characters long (maximum 4096); GetRandomPassword rejects it", [count(ex)]),
	_pf_smgss_fix, _pf_smgss_url) if {
	some name in resources_of_type("AWS::SecretsManager::Secret")
	g := _pf_smgss_gen(name)
	ex := object.get(g, "ExcludeCharacters", "")
	is_string(ex)
	count(ex) > 4096
}

# a required type whose every character is listed in ExcludeCharacters
_pf_smgss_alphabet := {
	"ExcludeNumbers": ["numbers", "0123456789"],
	"ExcludeUppercase": ["uppercase letters", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"],
	"ExcludeLowercase": ["lowercase letters", "abcdefghijklmnopqrstuvwxyz"],
	"ExcludePunctuation": ["punctuation", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"],
}

violation contains make_diag_full("pf-secretsmanager-generate-secret-string", "ERROR", name,
	"Properties.GenerateSecretString.ExcludeCharacters",
	sprintf("ExcludeCharacters removes every %s while that type is still required; GetRandomPassword fails with \"All characters of the desired type have been excluded.\"", [spec[0]]),
	_pf_smgss_fix, _pf_smgss_url) if {
	some name in resources_of_type("AWS::SecretsManager::Secret")
	g := _pf_smgss_gen(name)
	_pf_smgss_require(g)
	ex := object.get(g, "ExcludeCharacters", "")
	is_string(ex)
	some flag, spec in _pf_smgss_alphabet
	not _pf_smgss_flag(g, flag)
	alphabet := split(spec[1], "")
	count({c | some c in alphabet; contains(ex, c)}) == count(alphabet)
}

_pf_smgss_present(v) if {
	is_string(v)
	v != ""
}

_pf_smgss_present(v) if {
	not is_string(v)
	v != null
}

_pf_smgss_half(g) if {
	_pf_smgss_present(object.get(g, "SecretStringTemplate", null))
	not _pf_smgss_present(object.get(g, "GenerateStringKey", null))
}

_pf_smgss_half(g) if {
	_pf_smgss_present(object.get(g, "GenerateStringKey", null))
	not _pf_smgss_present(object.get(g, "SecretStringTemplate", null))
}

violation contains make_diag_full("pf-secretsmanager-generate-secret-string", "ERROR", name,
	"Properties.GenerateSecretString",
	"SecretStringTemplate and GenerateStringKey must be set together (an empty string counts as unset); the resource handler fails with \"SecretStringTemplate and GenerateStringKey must both be set or removed.\"",
	_pf_smgss_fix, _pf_smgss_url) if {
	some name in resources_of_type("AWS::SecretsManager::Secret")
	g := _pf_smgss_gen(name)
	_pf_smgss_half(g)
}

violation contains make_diag_full("pf-secretsmanager-generate-secret-string", "ERROR", name,
	"Properties.GenerateSecretString.SecretStringTemplate",
	"SecretStringTemplate is not a JSON object; the resource handler fails with \"Failed to parse SecretStringTemplate as JSON.\"",
	_pf_smgss_fix, _pf_smgss_url) if {
	some name in resources_of_type("AWS::SecretsManager::Secret")
	g := _pf_smgss_gen(name)
	t := object.get(g, "SecretStringTemplate", null)
	is_string(t)
	t != ""
	not _pf_smgss_jsonobj(t)
}

_pf_smgss_jsonobj(t) if {
	json.is_valid(t)
	is_object(json.unmarshal(t))
}
