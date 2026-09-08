package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-dynamodb-global-table-mrsc-ttl", "ERROR", name,
	"Properties.TimeToLiveSpecification",
	"TimeToLiveSpecification enables TTL on a MultiRegionConsistency STRONG global table; MRSC does not support TTL deletion",
	"Drop TTL, or use multi-Region eventual consistency (MREC)",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	_pf_ddb_mrsc(name)
	ttl := resolve(name, "Properties.TimeToLiveSpecification")
	is_object(ttl)
	object.get(ttl, "Enabled", null) == true
}
