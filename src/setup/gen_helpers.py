# Shared helpers for the GRC synthetic data generator (exec'd by 01_generate_synthetic_data)
from pyspark.sql import functions as F, Window as W

# CAT is set by the calling notebook (job parameter / widget `catalog`) before this file is exec'd.
CAT = globals().get("CAT") or "workspace"
LAND = f"/Volumes/{CAT}/grc_bronze/landing"
SYN = f"`{CAT}`.grc_synth"
REF = f"`{CAT}`.grc_ref"
START, END = "2026-07-29", "2026-10-27"
END_TS = "2026-10-27 23:59:59"

def u(col, salt):
    """Deterministic uniform [0,1) from a column + salt."""
    return F.pmod(F.hash(col, F.lit(salt)), F.lit(1000003)) / F.lit(1000003.0)

def pick(arr, col, salt):
    """Deterministic pick from a python list."""
    return F.element_at(F.array(*[F.lit(x) for x in arr]), (F.pmod(F.hash(col, F.lit(salt)), F.lit(len(arr))) + 1).cast("int"))

def wpick(pairs, r):
    """Weighted pick: pairs = [(value, cumulative_threshold), ...], r = uniform column."""
    e = None
    for v, t in pairs:
        e = F.when(r < t, F.lit(v)) if e is None else e.when(r < t, F.lit(v))
    return e.otherwise(F.lit(pairs[-1][0]))

def by_key(mapping, key_col, value_fn):
    """CASE WHEN key_col = k THEN value_fn(v) ..."""
    e = None
    for k, v in mapping.items():
        e = F.when(F.col(key_col) == k, value_fn(v)) if e is None else e.when(F.col(key_col) == k, value_fn(v))
    return e

def ts_in_day(day_col, col, salt, start_h=7, span_h=12):
    """Random timestamp within a day (business-hours skew)."""
    secs = (F.lit(start_h * 3600) + u(col, salt) * F.lit(span_h * 3600)).cast("int")
    return F.timestamp_seconds(F.unix_timestamp(F.col(day_col).cast("timestamp")) + secs)

def add_hours(ts_col, hours_col):
    return F.timestamp_seconds(F.unix_timestamp(ts_col) + (hours_col * 3600).cast("long"))

ACCOUNTS = [  # account_id, account_name, bu_id, env
    ("411122223333", "prod-payments", "BU-FIN", "production"),
    ("422233334444", "prod-core", "BU-ENG", "production"),
    ("433344445555", "prod-data", "BU-ENG", "production"),
    ("444455556666", "eng-ml", "BU-ENG", "non-production"),
    ("455566667777", "eng-dev", "BU-ENG", "non-production"),
    ("466677778888", "sales-crm-integrations", "BU-SAL", "production"),
    ("477788889999", "corp-shared", "BU-CORP", "production"),
    ("488899990000", "sandbox-ops", "BU-OPS", "non-production"),
]
REGIONS = ["us-east-1", "eu-west-1"]
