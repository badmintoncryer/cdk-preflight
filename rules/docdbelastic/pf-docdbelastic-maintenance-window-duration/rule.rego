package cdk_preflight

import rego.v1

_pf_dbemw_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdbelastic-cluster.html#cfn-docdbelastic-cluster-preferredmaintenancewindow"

_pf_dbemw_fix := "Give PreferredMaintenanceWindow (ddd:hh24:mi-ddd:hh24:mi, UTC) at least 30 minutes, e.g. sun:23:00-sun:23:30"

# to_number("03") is undefined in the engine's Rego build, so digits go through a table.
_pf_dbemw_digit := {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9}

_pf_dbemw_days := {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

# "hh:mi" -> minutes of day; undefined for anything else.
_pf_dbemw_min(t) := m if {
	regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, t)
	h := (_pf_dbemw_digit[substring(t, 0, 1)] * 10) + _pf_dbemw_digit[substring(t, 1, 1)]
	mi := (_pf_dbemw_digit[substring(t, 3, 1)] * 10) + _pf_dbemw_digit[substring(t, 4, 1)]
	m := (h * 60) + mi
}

# "ddd:hh24:mi-ddd:hh24:mi" -> length in minutes, wrapping around the week.
# A window that does not parse is left alone (the format itself is not this rule's constraint).
_pf_dbemw_minutes(w) := n if {
	parts := split(lower(w), "-")
	count(parts) == 2
	p1 := split(parts[0], ":")
	p2 := split(parts[1], ":")
	count(p1) == 3
	count(p2) == 3
	start := (_pf_dbemw_days[p1[0]] * 1440) + _pf_dbemw_min(sprintf("%s:%s", [p1[1], p1[2]]))
	end := (_pf_dbemw_days[p2[0]] * 1440) + _pf_dbemw_min(sprintf("%s:%s", [p2[1], p2[2]]))
	n := ((end - start) + 10080) % 10080
}

violation contains make_diag_full("pf-docdbelastic-maintenance-window-duration", "ERROR", name,
	"Properties.PreferredMaintenanceWindow",
	sprintf("the maintenance window '%s' is %d minutes long; CreateCluster fails with \"Maintenance window must be at least 30 minutes long.\"", [w, n]),
	_pf_dbemw_fix, _pf_dbemw_url) if {
	some name in resources_of_type("AWS::DocDBElastic::Cluster")
	w := resolve(name, "Properties.PreferredMaintenanceWindow")
	is_string(w)
	not input.resources[w]
	n := _pf_dbemw_minutes(w)
	n < 30
}
