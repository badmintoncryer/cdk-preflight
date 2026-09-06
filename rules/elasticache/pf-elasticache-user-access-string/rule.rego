package cdk_preflight

import rego.v1

_pf_ecas_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateUser.html"

_pf_ecas_fix := "Build the access string from on/off, ~key patterns, &channel patterns and +/- commands or @categories — passwords are set with the Passwords property, not in the string"

# Category names ElastiCache accepts (Redis ACL categories, measured 2026-09-06).
_pf_ecas_categories := {
	"all", "admin", "bitmap", "blocking", "connection", "dangerous", "fast",
	"geo", "hash", "hyperloglog", "keyspace", "list", "pubsub", "read",
	"scripting", "set", "sortedset", "slow", "stream", "string", "transaction", "write",
}

# Bare keywords the service accepts next to the +/-/~/& rules.
_pf_ecas_keywords := {"on", "off", "allkeys", "allchannels", "allcommands", "nocommands", "sanitize-payload", "skip-sanitize-payload", "clearselectors"}

# Password / reset rules belong to Redis but not to the ElastiCache user API.
_pf_ecas_rejected := {"nopass", "resetpass", "reset", "resetkeys", "resetchannels"}

_pf_ecas_tokens(name) := ts if {
	s := resolve(name, "Properties.AccessString")
	_pf_cachelib_lit(s)
	ts := [t | some t in split(lower(s), " "); t != ""]
}

violation contains make_diag_full("pf-elasticache-user-access-string", "ERROR", name,
	"Properties.AccessString",
	sprintf("the access string contains '%s'; the create call fails with \"Password rules are not supported in Elasticache access string\" (or \"reset rule is not supported in Elasticache user api\")", [tok]),
	_pf_ecas_fix, _pf_ecas_url) if {
	some name in resources_of_type("AWS::ElastiCache::User")
	some tok in _pf_ecas_tokens(name)
	tok in _pf_ecas_rejected
}

violation contains make_diag_full("pf-elasticache-user-access-string", "ERROR", name,
	"Properties.AccessString",
	sprintf("'%s' is not an access-string rule; the create call fails with \"The access-string is invalid.\"", [tok]),
	_pf_ecas_fix, _pf_ecas_url) if {
	some name in resources_of_type("AWS::ElastiCache::User")
	some tok in _pf_ecas_tokens(name)
	not tok in _pf_ecas_rejected
	not tok in _pf_ecas_keywords
	not startswith(tok, "~")
	not startswith(tok, "&")
	not startswith(tok, "+")
	not startswith(tok, "-")
	not startswith(tok, "%")
}

violation contains make_diag_full("pf-elasticache-user-access-string", "ERROR", name,
	"Properties.AccessString",
	sprintf("'%s' is not a Redis ACL category; the create call fails with \"Access string contains invalid category(s)\"", [tok]),
	_pf_ecas_fix, _pf_ecas_url) if {
	some name in resources_of_type("AWS::ElastiCache::User")
	some tok in _pf_ecas_tokens(name)
	some prefix in ["+@", "-@"]
	startswith(tok, prefix)
	cat := substring(tok, 2, -1)
	not cat in _pf_ecas_categories
}
