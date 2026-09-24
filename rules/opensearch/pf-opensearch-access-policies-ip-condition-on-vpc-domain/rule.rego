package cdk_preflight

import rego.v1

# AccessPolicies is an object in CDK output and a JSON string in hand-written
# templates; both shapes reach the same statement list. Two heads of one
# function are safe only because is_object and is_string are disjoint - two
# heads that can both bind for the same input are a runtime conflict.
_pf_osvpcip_doc(name) := d if {
	d := resolve(name, "Properties.AccessPolicies")
	is_object(d)
}

_pf_osvpcip_doc(name) := d if {
	s := resolve(name, "Properties.AccessPolicies")
	is_string(s)
	d := json.unmarshal(s)
}

# Two definitions instead of iterating the two keys: a second bare `some` in one
# rule body takes the whole pack down (AGENTS.md).
_pf_osvpcip_cond(c) if object.get(c, "IpAddress", "__pf_absent") != "__pf_absent"

_pf_osvpcip_cond(c) if object.get(c, "NotIpAddress", "__pf_absent") != "__pf_absent"

violation contains make_diag_full("pf-opensearch-access-policies-ip-condition-on-vpc-domain", "ERROR", name,
	"Properties.AccessPolicies",
	"the domain has VPCOptions, so an IP-based access policy is rejected with \"You can't attach an IP-based policy to a domain that has a VPC endpoint\"",
	"Drop the aws:SourceIp condition and control access with the security group on VPCOptions instead",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html#vpc-security") if {
	some name in _pf_os_domains
	_pf_os_has(name, "VPCOptions")
	stmts := object.get(_pf_osvpcip_doc(name), "Statement", [])
	is_array(stmts)
	some _i, st in stmts
	is_object(st)
	cond := object.get(st, "Condition", {})
	is_object(cond)
	_pf_osvpcip_cond(cond)
}
