package cdk_preflight

import rego.v1

# Shared helpers for the ECR rules (rules/ecr/pf-ecr-*).
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.
#
# The lifecycle policy is an opaque JSON string in both places it can appear:
# AWS::ECR::Repository LifecyclePolicy.LifecyclePolicyText and
# AWS::ECR::RepositoryCreationTemplate LifecyclePolicy. PutLifecyclePolicy
# validates the document itself, so the rules parse it here.

_pf_ecrlib_text(name) := s if {
	name in resources_of_type("AWS::ECR::Repository")
	s := resolve(name, "Properties.LifecyclePolicy.LifecyclePolicyText")
	is_string(s)
}

_pf_ecrlib_text(name) := s if {
	name in resources_of_type("AWS::ECR::RepositoryCreationTemplate")
	s := resolve(name, "Properties.LifecyclePolicy")
	is_string(s)
}

_pf_ecrlib_prop(name) := "Properties.LifecyclePolicy.LifecyclePolicyText" if {
	name in resources_of_type("AWS::ECR::Repository")
}

_pf_ecrlib_prop(name) := "Properties.LifecyclePolicy" if {
	name in resources_of_type("AWS::ECR::RepositoryCreationTemplate")
}

# Parsed policy document; undefined when the text is not JSON or not an object.
_pf_ecrlib_policy(name) := pol if {
	pol := json.unmarshal(_pf_ecrlib_text(name))
	is_object(pol)
}

_pf_ecrlib_rule_list(name) := rules if {
	rules := object.get(_pf_ecrlib_policy(name), "rules", null)
	is_array(rules)
}

# [name, index, rule object] for every rule of every lifecycle policy.
_pf_ecrlib_rules contains [name, i, r] if {
	some name, _ in input.resources
	some i, r in _pf_ecrlib_rule_list(name)
	is_object(r)
}

_pf_ecrlib_selection(r) := s if {
	s := object.get(r, "selection", null)
	is_object(s)
}

_pf_ecrlib_action(r) := a if {
	a := object.get(r, "action", null)
	is_object(a)
}

_pf_ecrlib_get(o, key) := v if {
	v := object.get(o, key, "__pf_absent")
	v != "__pf_absent"
}

_pf_ecrlib_absent(o, key) if object.get(o, key, "__pf_absent") == "__pf_absent"

# [partition, service, region, account, resource...] of a literal ARN.
_pf_ecrlib_arn(s) := parts if {
	is_string(s)
	startswith(s, "arn:")
	parts := split(s, ":")
	count(parts) >= 6
}

# Resource types that carry EncryptionConfiguration / ImageTagMutability.
_pf_ecrlib_repo_types := ["AWS::ECR::Repository", "AWS::ECR::RepositoryCreationTemplate"]

# Upstream registry URLs a pull through cache rule accepts (measured
# 2026-09-05 in ap-northeast-1; the check is case sensitive and any other URL
# is rejected with "The upstream registry URL <url> is invalid").
# The three "open" registries take no credential at all; the five "secret"
# ones require a Secrets Manager ARN; the ECR form authenticates with an IAM
# role instead.
_pf_ecrlib_ptc_secret_url := {
	"registry-1.docker.io": "docker-hub",
	"ghcr.io": "github-container-registry",
	"registry.gitlab.com": "gitlab-container-registry",
	"cgr.dev": "chainguard",
}

_pf_ecrlib_ptc_open_url := {
	"public.ecr.aws": "ecr-public",
	"registry.k8s.io": "k8s",
	"quay.io": "quay",
}

_pf_ecrlib_ptc_registry(url) := _pf_ecrlib_ptc_secret_url[url]

_pf_ecrlib_ptc_registry(url) := _pf_ecrlib_ptc_open_url[url]

_pf_ecrlib_ptc_registry(url) := "azure-container-registry" if {
	is_string(url)
	endswith(url, ".azurecr.io")
	count(url) > count(".azurecr.io")
}

_pf_ecrlib_ptc_registry(url) := "ecr" if {
	is_string(url)
	regex.match(`^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com$`, url)
}

# Registries that authenticate with a Secrets Manager secret.
_pf_ecrlib_ptc_needs_secret(url) if _pf_ecrlib_ptc_secret_url[url]

_pf_ecrlib_ptc_needs_secret(url) if _pf_ecrlib_ptc_registry(url) == "azure-container-registry"
