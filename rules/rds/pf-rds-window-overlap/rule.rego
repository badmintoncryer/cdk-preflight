package cdk_preflight

import rego.v1

# "HH:MM" -> minutes of day; undefined for anything else. Digits go
# through a lookup table because to_number rejects leading zeros
# (to_number("03") is undefined in the engine's Rego build).
_pf_rdswo_digit := {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9}

_pf_rdswo_min(t) := m if {
	is_string(t)
	regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, t)
	h := (_pf_rdswo_digit[substring(t, 0, 1)] * 10) + _pf_rdswo_digit[substring(t, 1, 1)]
	mi := (_pf_rdswo_digit[substring(t, 3, 1)] * 10) + _pf_rdswo_digit[substring(t, 4, 1)]
	m := (h * 60) + mi
}

# The backup window recurs daily, so a same-day maintenance window
# overlaps whenever the time-of-day intervals intersect.
violation contains make_diag_full("pf-rds-window-overlap", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("Backup window %s overlaps maintenance window %s; RDS rejects the pair (\"The backup window and maintenance window must not overlap.\")", [bw, mw]),
	"Separate the two windows in time",
	"https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	bw := resolve(name, "Properties.PreferredBackupWindow")
	is_string(bw)
	bp := split(bw, "-")
	count(bp) == 2
	bs := _pf_rdswo_min(bp[0])
	be := _pf_rdswo_min(bp[1])
	bs < be
	mw := resolve(name, "Properties.PreferredMaintenanceWindow")
	is_string(mw)
	mp := split(lower(mw), "-")
	count(mp) == 2
	m1 := split(mp[0], ":")
	m2 := split(mp[1], ":")
	count(m1) == 3
	count(m2) == 3
	m1[0] == m2[0]
	ms := _pf_rdswo_min(sprintf("%s:%s", [m1[1], m1[2]]))
	me := _pf_rdswo_min(sprintf("%s:%s", [m2[1], m2[2]]))
	ms < me
	bs < me
	ms < be
}
