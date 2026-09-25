package cdk_preflight

import rego.v1

# Shared helpers for the AWS::OpenSearchServerless policy rules (rules/aoss/pf-aoss-*).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.
#
# rules/_lib/opensearch.rego is for AWS::OpenSearchService::Domain and has
# nothing in common with Serverless, which hides every constraint worth a rule
# inside one opaque JSON string (`Properties.Policy`, 1-20480 chars in the CFN
# schema, no structure below it).
#
# Four resources carry that string and the top-level type is NOT the same for
# all of them: AccessPolicy (Type data) and SecurityPolicy (Type network) hold
# an ARRAY of blocks, SecurityPolicy (Type encryption) and LifecyclePolicy
# (Type retention) hold a single OBJECT. _pf_aoss_blocks_at normalizes the two
# so a rule iterates one shape and still reports a truthful property path.
#
# No numeric thresholds live here on purpose: test/structure.test.ts reads only
# rule.rego, so a boundary hidden in this file would skip the check.

# The parsed policy document. resolve() flattens Fn::Join / Fn::Sub over
# pseudo parameters (a CDK user's ${AWS::AccountId} inside a principal ARN)
# and is undefined when the text references another resource - which is what
# mutes every rule here on tokenized input.
_pf_aoss_doc(name) := d if {
	raw := resolve(name, "Properties.Policy")
	is_string(raw)
	d := json.unmarshal(raw)
}

# Policies of one kind: _pf_aoss_of("AWS::OpenSearchServerless::SecurityPolicy", "encryption").
_pf_aoss_of(rtype, ptype) := {name |
	some name in resources_of_type(rtype)
	resolve(name, "Properties.Type") == ptype
}

_pf_aoss_enc := _pf_aoss_of("AWS::OpenSearchServerless::SecurityPolicy", "encryption")

_pf_aoss_net := _pf_aoss_of("AWS::OpenSearchServerless::SecurityPolicy", "network")

_pf_aoss_data := _pf_aoss_of("AWS::OpenSearchServerless::AccessPolicy", "data")

_pf_aoss_life := _pf_aoss_of("AWS::OpenSearchServerless::LifecyclePolicy", "retention")

# [property path, block] for every top-level block, array shape or object shape.
_pf_aoss_blocks_at(name) := out if {
	d := _pf_aoss_doc(name)
	is_array(d)
	out := [[sprintf("Properties.Policy[%v]", [i]), b] |
		some i, b in d
		is_object(b)
	]
}

_pf_aoss_blocks_at(name) := [["Properties.Policy", d]] if {
	d := _pf_aoss_doc(name)
	is_object(d)
}

# [property path, rule object] for every Rules[] entry under every block.
_pf_aoss_rules_at(name) := [[sprintf("%v.Rules[%v]", [bp, i]), r] |
	some [bp, b] in _pf_aoss_blocks_at(name)
	rs := object.get(b, "Rules", null)
	is_array(rs)
	some i, r in rs
	is_object(r)
]

# The strings of a list-valued policy field. Undefined when the value is not a
# list, so a malformed document mutes the rule instead of guessing.
_pf_aoss_strings(v) := out if {
	is_array(v)
	out := [s | some s in v; is_string(s)]
}

# Every Resource string a policy names, as a set (for the duplicate check).
_pf_aoss_resource_set(name) := {res |
	some [_, r] in _pf_aoss_rules_at(name)
	some res in _pf_aoss_strings(object.get(r, "Resource", []))
}

# Resource patterns the server accepts, taken verbatim from the schema regexes
# CreateSecurityPolicy / CreateAccessPolicy / CreateLifecyclePolicy quote back
# in their rejection messages (2026-09-25, us-east-1). Note that the data and
# lifecycle index patterns differ: lifecycle also allows ~ and = in the index
# segment.
_pf_aoss_re_collection := `^collection/(?:[a-z][a-z0-9_-]{2,63}\*?|\*)$`

_pf_aoss_re_index_data := `^index/(?:[a-z][a-z0-9_-]{2,63}\*?|\*)/([a-z;0-9&$%][+.\-_a-z;0-9&$%]*\*?|\*)$`

_pf_aoss_re_index_life := `^index/(?:[a-z][a-z0-9_-]{2,63}\*?|\*)/([a-z;0-9&$%][+.~=\-_a-z;0-9&$%]*\*?|\*)$`

_pf_aoss_re_vpce := `^vpce-[a-zA-Z0-9]{8,20}$`

# Permissions per data-access ResourceType, from the enumerations the server
# lists when a Permission is rejected. The developer guide's 11 are not the
# whole set: DelegateAccess / RestoreSnapshot / DescribeSnapshot and the whole
# model / agent branches are missing there, so the rejection message is the
# source of truth (2026-09-25, us-east-1).
_pf_aoss_perms := {
	"collection": {
		"aoss:CreateCollectionItems", "aoss:DeleteCollectionItems",
		"aoss:UpdateCollectionItems", "aoss:DescribeCollectionItems",
		"aoss:RestoreSnapshot", "aoss:DescribeSnapshot", "aoss:*",
	},
	"index": {
		"aoss:ReadDocument", "aoss:WriteDocument", "aoss:CreateIndex",
		"aoss:DeleteIndex", "aoss:UpdateIndex", "aoss:DescribeIndex",
		"aoss:DelegateAccess", "aoss:RestoreSnapshot", "aoss:DescribeSnapshot",
		"aoss:*",
	},
	"model": {
		"aoss:DescribeMLResource", "aoss:CreateMLResource",
		"aoss:UpdateMLResource", "aoss:DeleteMLResource",
		"aoss:ExecuteMLResource", "aoss:*",
	},
	"agent": {
		"aoss:DescribeAgent", "aoss:SearchAgents", "aoss:CreateAgent",
		"aoss:UpdateAgent", "aoss:DeleteAgent", "aoss:InvokeAgent", "aoss:*",
	},
}

_pf_aoss_all_perms := {p |
	some rt in object.keys(_pf_aoss_perms)
	some p in _pf_aoss_perms[rt]
}

# The account a data-access principal belongs to: an IAM/STS ARN's account
# segment, or the second segment of saml/<account>/<config>/user|group/<name>.
# Undefined for anything else, so unknown principal shapes stay silent.
_pf_aoss_principal_account(p) := a if {
	parts := split(p, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] in {"iam", "sts"}
	a := parts[4]
	regex.match(`^[0-9]{12}$`, a)
}

_pf_aoss_principal_account(p) := a if {
	parts := split(p, "/")
	count(parts) >= 4
	parts[0] == "saml"
	a := parts[1]
	regex.match(`^[0-9]{12}$`, a)
}

# Region segment of an ARN, guarded so a non-ARN string never reaches a
# comparison against the deploy Region.
_pf_aoss_arn_region(s) := r if {
	is_string(s)
	parts := split(s, ":")
	count(parts) >= 6
	parts[0] == "arn"
	r := parts[3]
	r != ""
}

# Keys the OTHER SecurityPolicy type owns. CreateSecurityPolicy answers
# "$.<key>: is not defined in the schema and the schema does not allow
# additional properties" for each one that turns up on the wrong type
# (2026-09-25, us-east-1).
_pf_aoss_net_only_keys := {"AllowFromPublic", "SourceVPCEs", "SourceServices"}

_pf_aoss_enc_only_keys := {"AWSOwnedKey", "KmsARN"}

# Every resource that carries a Policy string, for the shared 10,240-byte limit.
_pf_aoss_policy_names := ((_pf_aoss_enc | _pf_aoss_net) | _pf_aoss_data) | _pf_aoss_life

# The options block CreateSecurityConfig demands for each Type.
_pf_aoss_sc_options := {
	"saml": "SamlOptions",
	"iamidentitycenter": "IamIdentityCenterOptions",
	"iamfederation": "IamFederationOptions",
}

# Raw Properties, for the presence checks resolve() cannot make: resolve is
# undefined both for "the property is absent" and for "the property is a token",
# and a required-property rule must not confuse the two.
_pf_aoss_props(name) := object.get(input.resources[name], "properties", {})

# Does an encryption policy Resource pattern cover this collection name?
# collection/* takes everything, a trailing * is a prefix, anything else is the
# exact name (the server's own pattern allows only those three shapes).
_pf_aoss_covers(res, cn) if {
	pat := _pf_aoss_pattern(res)
	pat == "*"
}

_pf_aoss_covers(res, cn) if {
	pat := _pf_aoss_pattern(res)
	endswith(pat, "*")
	startswith(cn, trim_suffix(pat, "*"))
}

_pf_aoss_covers(res, cn) if {
	pat := _pf_aoss_pattern(res)
	not endswith(pat, "*")
	pat == cn
}

_pf_aoss_pattern(res) := p if {
	is_string(res)
	startswith(res, "collection/")
	p := trim_prefix(res, "collection/")
}
