package cdk_preflight

import rego.v1

_pf_ecauth_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticache-replicationgroup.html"

_pf_ecauth_fix := "Set TransitEncryptionEnabled: true next to AuthToken and use 16-128 printable ASCII characters; slash, quote, double quote and at-sign are rejected"

violation contains make_diag_full("pf-elasticache-auth-token", "ERROR", name,
	"Properties.AuthToken",
	"AuthToken is set but TransitEncryptionEnabled is not true; the create call fails with \"The AUTH token is only supported when encryption-in-transit is enabled\"",
	_pf_ecauth_fix, _pf_ecauth_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	not _pf_cachelib_absent(name, "AuthToken")
	not _pf_ecauth_transit(name)
}

_pf_ecauth_transit(name) if resolve(name, "Properties.TransitEncryptionEnabled") == true

violation contains make_diag_full("pf-elasticache-auth-token", "ERROR", name,
	"Properties.AuthToken",
	sprintf("the AUTH token is %d characters; the create call fails with \"Invalid AuthToken provided\" outside 16-128", [count(tok)]),
	_pf_ecauth_fix, _pf_ecauth_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	tok := resolve(name, "Properties.AuthToken")
	_pf_cachelib_lit(tok)
	_pf_ecauth_bad_length(count(tok))
}

_pf_ecauth_bad_length(n) if n < 16

_pf_ecauth_bad_length(n) if n > 128

violation contains make_diag_full("pf-elasticache-auth-token", "ERROR", name,
	"Properties.AuthToken",
	sprintf("the AUTH token contains '%s'; the create call fails with \"Invalid AuthToken provided\" (/ ' \" @ are not accepted)", [ch]),
	_pf_ecauth_fix, _pf_ecauth_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	tok := resolve(name, "Properties.AuthToken")
	_pf_cachelib_lit(tok)
	some ch in ["/", "'", "\"", "@"]
	contains(tok, ch)
}
