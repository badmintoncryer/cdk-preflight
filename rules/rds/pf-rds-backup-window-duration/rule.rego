package cdk_preflight

import rego.v1

# "HH:MM" -> minutes of day; undefined for anything else. Digits go
# through a lookup table because to_number rejects leading zeros
# (to_number("03") is undefined in the engine's Rego build).
_pf_rdswd_digit := {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9}

_pf_rdswd_min(t) := m if {
	is_string(t)
	regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, t)
	h := (_pf_rdswd_digit[substring(t, 0, 1)] * 10) + _pf_rdswd_digit[substring(t, 1, 1)]
	mi := (_pf_rdswd_digit[substring(t, 3, 1)] * 10) + _pf_rdswd_digit[substring(t, 4, 1)]
	m := (h * 60) + mi
}

violation contains make_diag_full("pf-rds-backup-window-duration", "ERROR", name,
	"Properties.PreferredBackupWindow",
	sprintf("PreferredBackupWindow '%s' is only %v minutes; RDS requires at least 30 (\"Backup window must be at least 30 minutes.\")", [w, d]),
	"Widen the window to 30 minutes or more",
	"https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	w := resolve(name, "Properties.PreferredBackupWindow")
	is_string(w)
	parts := split(w, "-")
	count(parts) == 2
	s := _pf_rdswd_min(parts[0])
	e := _pf_rdswd_min(parts[1])
	d := ((e - s) + 1440) % 1440
	d < 30
}
