package cdk_preflight

import rego.v1

_pf_ssmms_url := "https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html"

_pf_ssmms_fix := "Fix the schedule expression (see message), drop ScheduleOffset unless the cron targets e.g. TUE#3 or 6L, write dates as 2030-01-01T00:00:00Z / +09:00, and use IANA zone names such as Asia/Tokyo"

_pf_ssmms_sched(name) := s if {
	s := resolve(name, "Properties.Schedule")
	is_string(s)
}

_pf_ssmms_kind(s) := "rate" if startswith(lower(s), "rate(")

_pf_ssmms_kind(s) := "cron" if startswith(lower(s), "cron(")

_pf_ssmms_kind(s) := "at" if startswith(lower(s), "at(")

violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.Schedule",
	sprintf("'%s' is not a rate(), cron() or at() expression; CreateMaintenanceWindow fails with \"Schedule expressions must have the following syntax: rate(<number>\\s?(minutes?|hours?|days?)), cron(<cron_expression>) or at(yyyy-MM-dd'T'HH:mm:ss).\"", [s]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	s := _pf_ssmms_sched(name)
	not _pf_ssmms_kind(s)
}

_pf_ssmms_rate(s) := to_number(m[0][1]) if {
	m := regex.find_all_string_submatch_n("^[Rr]ate\\(([0-9]+) ?(minutes?|hours?|days?)\\)$", s, 1)
	count(m) == 1
}

violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.Schedule",
	sprintf("'%s' is not rate(<number> minutes|hours|days) (no extra spaces, no seconds); CreateMaintenanceWindow rejects the schedule syntax", [s]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	s := _pf_ssmms_sched(name)
	_pf_ssmms_kind(s) == "rate"
	not _pf_ssmms_rate(s)
}

violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.Schedule",
	sprintf("'%s' has a zero interval; CreateMaintenanceWindow fails with \"Invalid schedule frequency\"", [s]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	s := _pf_ssmms_sched(name)
	_pf_ssmms_rate(s) == 0
}

violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.Schedule",
	sprintf("'%s' is not at(yyyy-MM-ddTHH:mm[:ss]) (no time zone suffix); CreateMaintenanceWindow fails with \"Invalid schedule at DateTime expression\"", [s]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	s := _pf_ssmms_sched(name)
	_pf_ssmms_kind(s) == "at"
	not regex.match("^(?i)at\\([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(:[0-9]{2})?\\)$", s)
}

# cron(): 6 fields (min hour dom month dow year) or 7 with leading seconds
_pf_ssmms_fields(s) := f if {
	regex.match("^(?i)cron\\(.*\\)$", s)
	f := [x | some x in split(substring(s, 5, count(s) - 6), " "); x != ""]
}

# ponytail: only the documented 6- and 7-field forms are checked (the service also tolerates extra trailing fields)
_pf_ssmms_six(f) := f if count(f) == 6

_pf_ssmms_six(f) := array.slice(f, 1, 7) if count(f) == 7

violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.Schedule",
	sprintf("'%s' has fewer than the 6 cron fields (min hour day-of-month month day-of-week year); CreateMaintenanceWindow fails with \"Invalid CRON expression\"", [s]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	s := _pf_ssmms_sched(name)
	_pf_ssmms_kind(s) == "cron"
	count(_pf_ssmms_fields(s)) < 6
}

# numbers inside a field (before any '/' step) must stay in range; '#n' must be 1..5
_pf_ssmms_nums(field) := [to_number(n) | some item in split(field, ","); base := split(item, "/")[0]; some n in regex.find_n("[0-9]+", base, -1)]

_pf_ssmms_ranges := {0: [0, 59, "minutes/seconds"], 1: [0, 23, "hours"], 2: [1, 31, "day-of-month"], 3: [1, 12, "month"], 4: [1, 7, "day-of-week"]}

violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.Schedule",
	sprintf("'%s': %v is out of range for the %s field (%d..%d); CreateMaintenanceWindow fails with \"Invalid CRON expression\"", [s, n, r[2], r[0], r[1]]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	s := _pf_ssmms_sched(name)
	f := _pf_ssmms_six(_pf_ssmms_fields(s))
	some i, r in _pf_ssmms_ranges
	field := replace(f[i], "#", "/")
	some n in _pf_ssmms_nums(field)
	_pf_ssmms_outside(n, r[0], r[1])
}

_pf_ssmms_outside(n, lo, _) if n < lo

_pf_ssmms_outside(n, _, hi) if n > hi

violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.Schedule",
	sprintf("'%s': '#%s' must select the 1st..5th weekday of the month; CreateMaintenanceWindow fails with \"Invalid CRON expression\"", [s, m[1]]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	s := _pf_ssmms_sched(name)
	f := _pf_ssmms_six(_pf_ssmms_fields(s))
	some m in regex.find_all_string_submatch_n("#([0-9]+)", f[4], -1)
	_pf_ssmms_outside(to_number(m[1]), 1, 5)
}

violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.Schedule",
	sprintf("'%s' sets both day-of-month and day-of-week; one of them must be ?; CreateMaintenanceWindow fails with \"Specifying both a day-of-week AND a day-of-month parameter is not supported.\"", [s]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	s := _pf_ssmms_sched(name)
	f := _pf_ssmms_six(_pf_ssmms_fields(s))
	f[2] != "?"
	f[4] != "?"
}

violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.Schedule",
	sprintf("'%s' has ? in both day-of-month and day-of-week; exactly one of them must be ?; CreateMaintenanceWindow fails with \"Invalid CRON expression\"", [s]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	s := _pf_ssmms_sched(name)
	f := _pf_ssmms_six(_pf_ssmms_fields(s))
	f[2] == "?"
	f[4] == "?"
}

# ScheduleOffset
violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.ScheduleOffset",
	"ScheduleOffset only applies to cron expressions that target a specific weekday of the month (e.g. TUE#3 or 6L); CreateMaintenanceWindow fails with \"An offset can't be added to the specified schedule.\"",
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	object.get(input.resources[name].properties, "ScheduleOffset", "__pf_absent") != "__pf_absent"
	s := _pf_ssmms_sched(name)
	not _pf_ssmms_offset_ok(s)
}

_pf_ssmms_offset_ok(s) if {
	f := _pf_ssmms_six(_pf_ssmms_fields(s))
	regex.match("[#L]", f[4])
}

# StartDate / EndDate
_pf_ssmms_date(name, k) := d if {
	d := resolve(name, sprintf("Properties.%s", [k]))
	is_string(d)
}

_pf_ssmms_iso(d) if regex.match("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(:[0-9]{2}(\\.[0-9]+)?)?(Z|[+-][0-9]{2}:[0-9]{2})$", d)

violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("%s '%s' is not an ISO-8601 date-time with an offset; CreateMaintenanceWindow fails with \"DateTime %s is malformed, format either must contain an offset - e.g. '2018-01-01T00:00:00-02:00' or '2018-01-01T00:00:00Z'\"", [k, d, d]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	some k in ["StartDate", "EndDate"]
	d := _pf_ssmms_date(name, k)
	not _pf_ssmms_iso(d)
}

# same-suffix dates compare lexicographically
violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.EndDate",
	sprintf("EndDate %s is not after StartDate %s; CreateMaintenanceWindow fails with \"Window start date must be before window end date\"", [e, st]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	st := _pf_ssmms_date(name, "StartDate")
	e := _pf_ssmms_date(name, "EndDate")
	_pf_ssmms_iso(st)
	_pf_ssmms_iso(e)
	substring(st, 19, -1) == substring(e, 19, -1)
	e <= st
}

# ScheduleTimezone
# ponytail: the engine caps Rego source lines at 1024 columns, so the list is wrapped
_pf_ssmms_zones := [
	"Africa/Abidjan",
	"Africa/Accra",
	"Africa/Addis_Ababa",
	"Africa/Algiers",
	"Africa/Asmara",
	"Africa/Asmera",
	"Africa/Bamako",
	"Africa/Bangui",
	"Africa/Banjul",
	"Africa/Bissau",
	"Africa/Blantyre",
	"Africa/Brazzaville",
	"Africa/Bujumbura",
	"Africa/Cairo",
	"Africa/Casablanca",
	"Africa/Ceuta",
	"Africa/Conakry",
	"Africa/Dakar",
	"Africa/Dar_es_Salaam",
	"Africa/Djibouti",
	"Africa/Douala",
	"Africa/El_Aaiun",
	"Africa/Freetown",
	"Africa/Gaborone",
	"Africa/Harare",
	"Africa/Johannesburg",
	"Africa/Juba",
	"Africa/Kampala",
	"Africa/Khartoum",
	"Africa/Kigali",
	"Africa/Kinshasa",
	"Africa/Lagos",
	"Africa/Libreville",
	"Africa/Lome",
	"Africa/Luanda",
	"Africa/Lubumbashi",
	"Africa/Lusaka",
	"Africa/Malabo",
	"Africa/Maputo",
	"Africa/Maseru",
	"Africa/Mbabane",
	"Africa/Mogadishu",
	"Africa/Monrovia",
	"Africa/Nairobi",
	"Africa/Ndjamena",
	"Africa/Niamey",
	"Africa/Nouakchott",
	"Africa/Ouagadougou",
	"Africa/Porto-Novo",
	"Africa/Sao_Tome",
	"Africa/Timbuktu",
	"Africa/Tripoli",
	"Africa/Tunis",
	"Africa/Windhoek",
	"America/Adak",
	"America/Anchorage",
	"America/Anguilla",
	"America/Antigua",
	"America/Araguaina",
	"America/Argentina/Buenos_Aires",
	"America/Argentina/Catamarca",
	"America/Argentina/ComodRivadavia",
	"America/Argentina/Cordoba",
	"America/Argentina/Jujuy",
	"America/Argentina/La_Rioja",
	"America/Argentina/Mendoza",
	"America/Argentina/Rio_Gallegos",
	"America/Argentina/Salta",
	"America/Argentina/San_Juan",
	"America/Argentina/San_Luis",
	"America/Argentina/Tucuman",
	"America/Argentina/Ushuaia",
	"America/Aruba",
	"America/Asuncion",
	"America/Atikokan",
	"America/Atka",
	"America/Bahia",
	"America/Bahia_Banderas",
	"America/Barbados",
	"America/Belem",
	"America/Belize",
	"America/Blanc-Sablon",
	"America/Boa_Vista",
	"America/Bogota",
	"America/Boise",
	"America/Buenos_Aires",
	"America/Cambridge_Bay",
	"America/Campo_Grande",
	"America/Cancun",
	"America/Caracas",
	"America/Catamarca",
	"America/Cayenne",
	"America/Cayman",
	"America/Chicago",
	"America/Chihuahua",
	"America/Ciudad_Juarez",
	"America/Coral_Harbour",
	"America/Cordoba",
	"America/Costa_Rica",
	"America/Coyhaique",
	"America/Creston",
	"America/Cuiaba",
	"America/Curacao",
	"America/Danmarkshavn",
	"America/Dawson",
	"America/Dawson_Creek",
	"America/Denver",
	"America/Detroit",
	"America/Dominica",
	"America/Edmonton",
	"America/Eirunepe",
	"America/El_Salvador",
	"America/Ensenada",
	"America/Fort_Nelson",
	"America/Fort_Wayne",
	"America/Fortaleza",
	"America/Glace_Bay",
	"America/Godthab",
	"America/Goose_Bay",
	"America/Grand_Turk",
	"America/Grenada",
	"America/Guadeloupe",
	"America/Guatemala",
	"America/Guayaquil",
	"America/Guyana",
	"America/Halifax",
	"America/Havana",
	"America/Hermosillo",
	"America/Indiana/Indianapolis",
	"America/Indiana/Knox",
	"America/Indiana/Marengo",
	"America/Indiana/Petersburg",
	"America/Indiana/Tell_City",
	"America/Indiana/Vevay",
	"America/Indiana/Vincennes",
	"America/Indiana/Winamac",
	"America/Indianapolis",
	"America/Inuvik",
	"America/Iqaluit",
	"America/Jamaica",
	"America/Jujuy",
	"America/Juneau",
	"America/Kentucky/Louisville",
	"America/Kentucky/Monticello",
	"America/Knox_IN",
	"America/Kralendijk",
	"America/La_Paz",
	"America/Lima",
	"America/Los_Angeles",
	"America/Louisville",
	"America/Lower_Princes",
	"America/Maceio",
	"America/Managua",
	"America/Manaus",
	"America/Marigot",
	"America/Martinique",
	"America/Matamoros",
	"America/Mazatlan",
	"America/Mendoza",
	"America/Menominee",
	"America/Merida",
	"America/Metlakatla",
	"America/Mexico_City",
	"America/Miquelon",
	"America/Moncton",
	"America/Monterrey",
	"America/Montevideo",
	"America/Montreal",
	"America/Montserrat",
	"America/Nassau",
	"America/New_York",
	"America/Nipigon",
	"America/Nome",
	"America/Noronha",
	"America/North_Dakota/Beulah",
	"America/North_Dakota/Center",
	"America/North_Dakota/New_Salem",
	"America/Nuuk",
	"America/Ojinaga",
	"America/Panama",
	"America/Pangnirtung",
	"America/Paramaribo",
	"America/Phoenix",
	"America/Port-au-Prince",
	"America/Port_of_Spain",
	"America/Porto_Acre",
	"America/Porto_Velho",
	"America/Puerto_Rico",
	"America/Punta_Arenas",
	"America/Rainy_River",
	"America/Rankin_Inlet",
	"America/Recife",
	"America/Regina",
	"America/Resolute",
	"America/Rio_Branco",
	"America/Rosario",
	"America/Santa_Isabel",
	"America/Santarem",
	"America/Santiago",
	"America/Santo_Domingo",
	"America/Sao_Paulo",
	"America/Scoresbysund",
	"America/Shiprock",
	"America/Sitka",
	"America/St_Barthelemy",
	"America/St_Johns",
	"America/St_Kitts",
	"America/St_Lucia",
	"America/St_Thomas",
	"America/St_Vincent",
	"America/Swift_Current",
	"America/Tegucigalpa",
	"America/Thule",
	"America/Thunder_Bay",
	"America/Tijuana",
	"America/Toronto",
	"America/Tortola",
	"America/Vancouver",
	"America/Virgin",
	"America/Whitehorse",
	"America/Winnipeg",
	"America/Yakutat",
	"America/Yellowknife",
	"Antarctica/Casey",
	"Antarctica/Davis",
	"Antarctica/DumontDUrville",
	"Antarctica/Macquarie",
	"Antarctica/Mawson",
	"Antarctica/McMurdo",
	"Antarctica/Palmer",
	"Antarctica/Rothera",
	"Antarctica/South_Pole",
	"Antarctica/Syowa",
	"Antarctica/Troll",
	"Antarctica/Vostok",
	"Arctic/Longyearbyen",
	"Asia/Aden",
	"Asia/Almaty",
	"Asia/Amman",
	"Asia/Anadyr",
	"Asia/Aqtau",
	"Asia/Aqtobe",
	"Asia/Ashgabat",
	"Asia/Ashkhabad",
	"Asia/Atyrau",
	"Asia/Baghdad",
	"Asia/Bahrain",
	"Asia/Baku",
	"Asia/Bangkok",
	"Asia/Barnaul",
	"Asia/Beirut",
	"Asia/Bishkek",
	"Asia/Brunei",
	"Asia/Calcutta",
	"Asia/Chita",
	"Asia/Choibalsan",
	"Asia/Chongqing",
	"Asia/Chungking",
	"Asia/Colombo",
	"Asia/Dacca",
	"Asia/Damascus",
	"Asia/Dhaka",
	"Asia/Dili",
	"Asia/Dubai",
	"Asia/Dushanbe",
	"Asia/Famagusta",
	"Asia/Gaza",
	"Asia/Harbin",
	"Asia/Hebron",
	"Asia/Ho_Chi_Minh",
	"Asia/Hong_Kong",
	"Asia/Hovd",
	"Asia/Irkutsk",
	"Asia/Istanbul",
	"Asia/Jakarta",
	"Asia/Jayapura",
	"Asia/Jerusalem",
	"Asia/Kabul",
	"Asia/Kamchatka",
	"Asia/Karachi",
	"Asia/Kashgar",
	"Asia/Kathmandu",
	"Asia/Katmandu",
	"Asia/Khandyga",
	"Asia/Kolkata",
	"Asia/Krasnoyarsk",
	"Asia/Kuala_Lumpur",
	"Asia/Kuching",
	"Asia/Kuwait",
	"Asia/Macao",
	"Asia/Macau",
	"Asia/Magadan",
	"Asia/Makassar",
	"Asia/Manila",
	"Asia/Muscat",
	"Asia/Nicosia",
	"Asia/Novokuznetsk",
	"Asia/Novosibirsk",
	"Asia/Omsk",
	"Asia/Oral",
	"Asia/Phnom_Penh",
	"Asia/Pontianak",
	"Asia/Pyongyang",
	"Asia/Qatar",
	"Asia/Qostanay",
	"Asia/Qyzylorda",
	"Asia/Rangoon",
	"Asia/Riyadh",
	"Asia/Saigon",
	"Asia/Sakhalin",
	"Asia/Samarkand",
	"Asia/Seoul",
	"Asia/Shanghai",
	"Asia/Singapore",
	"Asia/Srednekolymsk",
	"Asia/Taipei",
	"Asia/Tashkent",
	"Asia/Tbilisi",
	"Asia/Tehran",
	"Asia/Tel_Aviv",
	"Asia/Thimbu",
	"Asia/Thimphu",
	"Asia/Tokyo",
	"Asia/Tomsk",
	"Asia/Ujung_Pandang",
	"Asia/Ulaanbaatar",
	"Asia/Ulan_Bator",
	"Asia/Urumqi",
	"Asia/Ust-Nera",
	"Asia/Vientiane",
	"Asia/Vladivostok",
	"Asia/Yakutsk",
	"Asia/Yangon",
	"Asia/Yekaterinburg",
	"Asia/Yerevan",
	"Atlantic/Azores",
	"Atlantic/Bermuda",
	"Atlantic/Canary",
	"Atlantic/Cape_Verde",
	"Atlantic/Faeroe",
	"Atlantic/Faroe",
	"Atlantic/Jan_Mayen",
	"Atlantic/Madeira",
	"Atlantic/Reykjavik",
	"Atlantic/South_Georgia",
	"Atlantic/St_Helena",
	"Atlantic/Stanley",
	"Australia/ACT",
	"Australia/Adelaide",
	"Australia/Brisbane",
	"Australia/Broken_Hill",
	"Australia/Canberra",
	"Australia/Currie",
	"Australia/Darwin",
	"Australia/Eucla",
	"Australia/Hobart",
	"Australia/LHI",
	"Australia/Lindeman",
	"Australia/Lord_Howe",
	"Australia/Melbourne",
	"Australia/NSW",
	"Australia/North",
	"Australia/Perth",
	"Australia/Queensland",
	"Australia/South",
	"Australia/Sydney",
	"Australia/Tasmania",
	"Australia/Victoria",
	"Australia/West",
	"Australia/Yancowinna",
	"Brazil/Acre",
	"Brazil/DeNoronha",
	"Brazil/East",
	"Brazil/West",
	"CET",
	"CST6CDT",
	"Canada/Atlantic",
	"Canada/Central",
	"Canada/Eastern",
	"Canada/Mountain",
	"Canada/Newfoundland",
	"Canada/Pacific",
	"Canada/Saskatchewan",
	"Canada/Yukon",
	"Chile/Continental",
	"Chile/EasterIsland",
	"Cuba",
	"EET",
	"EST",
	"EST5EDT",
	"Egypt",
	"Eire",
	"Etc/GMT",
	"Etc/GMT+0",
	"Etc/GMT+1",
	"Etc/GMT+10",
	"Etc/GMT+11",
	"Etc/GMT+12",
	"Etc/GMT+2",
	"Etc/GMT+3",
	"Etc/GMT+4",
	"Etc/GMT+5",
	"Etc/GMT+6",
	"Etc/GMT+7",
	"Etc/GMT+8",
	"Etc/GMT+9",
	"Etc/GMT-0",
	"Etc/GMT-1",
	"Etc/GMT-10",
	"Etc/GMT-11",
	"Etc/GMT-12",
	"Etc/GMT-13",
	"Etc/GMT-14",
	"Etc/GMT-2",
	"Etc/GMT-3",
	"Etc/GMT-4",
	"Etc/GMT-5",
	"Etc/GMT-6",
	"Etc/GMT-7",
	"Etc/GMT-8",
	"Etc/GMT-9",
	"Etc/GMT0",
	"Etc/Greenwich",
	"Etc/UCT",
	"Etc/UTC",
	"Etc/Universal",
	"Etc/Zulu",
	"Europe/Amsterdam",
	"Europe/Andorra",
	"Europe/Astrakhan",
	"Europe/Athens",
	"Europe/Belfast",
	"Europe/Belgrade",
	"Europe/Berlin",
	"Europe/Bratislava",
	"Europe/Brussels",
	"Europe/Bucharest",
	"Europe/Budapest",
	"Europe/Busingen",
	"Europe/Chisinau",
	"Europe/Copenhagen",
	"Europe/Dublin",
	"Europe/Gibraltar",
	"Europe/Guernsey",
	"Europe/Helsinki",
	"Europe/Isle_of_Man",
	"Europe/Istanbul",
	"Europe/Jersey",
	"Europe/Kaliningrad",
	"Europe/Kiev",
	"Europe/Kirov",
	"Europe/Kyiv",
	"Europe/Lisbon",
	"Europe/Ljubljana",
	"Europe/London",
	"Europe/Luxembourg",
	"Europe/Madrid",
	"Europe/Malta",
	"Europe/Mariehamn",
	"Europe/Minsk",
	"Europe/Monaco",
	"Europe/Moscow",
	"Europe/Nicosia",
	"Europe/Oslo",
	"Europe/Paris",
	"Europe/Podgorica",
	"Europe/Prague",
	"Europe/Riga",
	"Europe/Rome",
	"Europe/Samara",
	"Europe/San_Marino",
	"Europe/Sarajevo",
	"Europe/Saratov",
	"Europe/Simferopol",
	"Europe/Skopje",
	"Europe/Sofia",
	"Europe/Stockholm",
	"Europe/Tallinn",
	"Europe/Tirane",
	"Europe/Tiraspol",
	"Europe/Ulyanovsk",
	"Europe/Uzhgorod",
	"Europe/Vaduz",
	"Europe/Vatican",
	"Europe/Vienna",
	"Europe/Vilnius",
	"Europe/Volgograd",
	"Europe/Warsaw",
	"Europe/Zagreb",
	"Europe/Zaporozhye",
	"Europe/Zurich",
	"Factory",
	"GB",
	"GB-Eire",
	"GMT",
	"GMT+0",
	"GMT-0",
	"GMT0",
	"Greenwich",
	"HST",
	"Hongkong",
	"Iceland",
	"Indian/Antananarivo",
	"Indian/Chagos",
	"Indian/Christmas",
	"Indian/Cocos",
	"Indian/Comoro",
	"Indian/Kerguelen",
	"Indian/Mahe",
	"Indian/Maldives",
	"Indian/Mauritius",
	"Indian/Mayotte",
	"Indian/Reunion",
	"Iran",
	"Israel",
	"Jamaica",
	"Japan",
	"Kwajalein",
	"Libya",
	"MET",
	"MST",
	"MST7MDT",
	"Mexico/BajaNorte",
	"Mexico/BajaSur",
	"Mexico/General",
	"NZ",
	"NZ-CHAT",
	"Navajo",
	"PRC",
	"PST8PDT",
	"Pacific/Apia",
	"Pacific/Auckland",
	"Pacific/Bougainville",
	"Pacific/Chatham",
	"Pacific/Chuuk",
	"Pacific/Easter",
	"Pacific/Efate",
	"Pacific/Enderbury",
	"Pacific/Fakaofo",
	"Pacific/Fiji",
	"Pacific/Funafuti",
	"Pacific/Galapagos",
	"Pacific/Gambier",
	"Pacific/Guadalcanal",
	"Pacific/Guam",
	"Pacific/Honolulu",
	"Pacific/Johnston",
	"Pacific/Kanton",
	"Pacific/Kiritimati",
	"Pacific/Kosrae",
	"Pacific/Kwajalein",
	"Pacific/Majuro",
	"Pacific/Marquesas",
	"Pacific/Midway",
	"Pacific/Nauru",
	"Pacific/Niue",
	"Pacific/Norfolk",
	"Pacific/Noumea",
	"Pacific/Pago_Pago",
	"Pacific/Palau",
	"Pacific/Pitcairn",
	"Pacific/Pohnpei",
	"Pacific/Ponape",
	"Pacific/Port_Moresby",
	"Pacific/Rarotonga",
	"Pacific/Saipan",
	"Pacific/Samoa",
	"Pacific/Tahiti",
	"Pacific/Tarawa",
	"Pacific/Tongatapu",
	"Pacific/Truk",
	"Pacific/Wake",
	"Pacific/Wallis",
	"Pacific/Yap",
	"Poland",
	"Portugal",
	"ROC",
	"ROK",
	"Singapore",
	"Turkey",
	"UCT",
	"US/Alaska",
	"US/Aleutian",
	"US/Arizona",
	"US/Central",
	"US/East-Indiana",
	"US/Eastern",
	"US/Hawaii",
	"US/Indiana-Starke",
	"US/Michigan",
	"US/Mountain",
	"US/Pacific",
	"US/Samoa",
	"UTC",
	"Universal",
	"W-SU",
	"WET",
	"Zulu",
]

violation contains make_diag_full("pf-ssm-maintenance-window-schedule", "ERROR", name,
	"Properties.ScheduleTimezone",
	sprintf("'%s' is not an IANA time zone name (case-sensitive, e.g. Asia/Tokyo) or a ±HH:MM offset; CreateMaintenanceWindow fails with \"%s is a malformed timezone. Please refer to the IANA time zone database for a valid timezones.\"", [tz, tz]),
	_pf_ssmms_fix, _pf_ssmms_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	tz := resolve(name, "Properties.ScheduleTimezone")
	is_string(tz)
	not tz in _pf_ssmms_zones
	not regex.match("^[+-][0-9]{2}:?[0-9]{2}$", tz)
}
