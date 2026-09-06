package cdk_preflight

import rego.v1

_pf_ecugd_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateUserGroup.html"

_pf_ecugd_fix := "Add a user whose UserName is default to a Redis user group; give Valkey group members a password or IAM authentication"

# UserIds resolve to the logical ids of AWS::ElastiCache::User resources in the
# same template, which is where the user name and auth mode can be read.
_pf_ecugd_members(name) := ids if {
	ids := resolve(name, "Properties.UserIds")
	is_array(ids)
}

_pf_ecugd_has_default(name) if {
	some uid in _pf_ecugd_members(name)
	uid in resources_of_type("AWS::ElastiCache::User")
	lower(resolve(uid, "Properties.UserName")) == "default"
}

# A member the template does not declare could still be the default user.
_pf_ecugd_has_default(name) if {
	some uid in _pf_ecugd_members(name)
	not uid in resources_of_type("AWS::ElastiCache::User")
}

violation contains make_diag_full("pf-elasticache-user-group-default-user", "ERROR", name,
	"Properties.UserIds",
	"the Redis user group has no member named default; CreateUserGroup fails with \"Redis user group needs to contain a user with the user name default.\"",
	_pf_ecugd_fix, _pf_ecugd_url) if {
	some name in resources_of_type("AWS::ElastiCache::UserGroup")
	lower(resolve(name, "Properties.Engine")) == "redis"
	not _pf_ecugd_has_default(name)
}

violation contains make_diag_full("pf-elasticache-user-group-default-user", "ERROR", name,
	"Properties.UserIds",
	sprintf("user '%s' needs no password but the group runs Valkey; CreateUserGroup fails with \"No password user %s cannot be added to user group with engine Valkey\"", [uid, uid]),
	_pf_ecugd_fix, _pf_ecugd_url) if {
	some name in resources_of_type("AWS::ElastiCache::UserGroup")
	lower(resolve(name, "Properties.Engine")) == "valkey"
	some uid in _pf_ecugd_members(name)
	uid in resources_of_type("AWS::ElastiCache::User")
	resolve(uid, "Properties.NoPasswordRequired") == true
}
