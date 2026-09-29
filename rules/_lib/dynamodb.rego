package cdk_preflight

import rego.v1

# Shared helpers for the AWS::DynamoDB::GlobalTable rules. MRSC (multi-Region
# strong consistency) constrains the replica set as a whole, so several rules
# need the same notion of "which Regions does this table touch".
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

_pf_ddb_mrsc(name) if resolve(name, "Properties.MultiRegionConsistency") == "STRONG"

_pf_ddb_regions(name, prop) := {r |
	some x in flatten_list(name, sprintf("Properties.%s", [prop]))
	r := object.get(x.value, "Region", null)
	is_string(r)
}

_pf_ddb_replica_regions(name) := _pf_ddb_regions(name, "Replicas")

_pf_ddb_witness_regions(name) := _pf_ddb_regions(name, "GlobalTableWitnesses")
