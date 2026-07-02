"""
Attendance Tracker — Backend Logic
Ported from attendancetracker.py (Streamlit) to plain Python for Flask.
"""
import io
import datetime
import pandas as pd
from io import BytesIO

SOC_SHIFT_TIMES = {
    "morning":   datetime.time(7, 0, 0),
    "afternoon": datetime.time(14, 0, 0),
    "night":     datetime.time(19, 0, 0),
}
CUTOFF   = datetime.time(8, 30, 0)
WORKDAYS = {0, 1, 2, 3, 4}   # Mon–Fri

STANDARD_COLS = {
    "time": "Time", "door name": "Door Name",
    "event description": "Event Description",
    "personnel id": "Personnel ID",
    "first name": "First Name", "last name": "Last Name",
    "door number": "Door Number",
}

TARGET_DOORS  = ["Main entrance Ground Flr", "Main entrance Upfloor"]
TARGET_EVENTS = ["Password", "Normal Open"]


def _normalize_columns(df):
    return df.rename(columns={
        c: STANDARD_COLS.get(str(c).strip().lower(), str(c).strip())
        for c in df.columns
    })


def _has_required_cols(cols):
    lc = [str(c).strip().lower() for c in cols]
    return all(t in lc for t in ["time", "door name", "event description"])


def _load_file(file_info: dict) -> pd.DataFrame:
    """Load a single file dict {'name': str, 'data': bytes} into DataFrame."""
    name  = file_info["name"]
    data  = file_info["data"]
    bio   = BytesIO(data)
    if name.lower().endswith(".csv"):
        df = pd.read_csv(bio)
        df.columns = df.columns.astype(str).str.strip()
        return _normalize_columns(df)

    # Excel — may have multiple sheets
    sheets = pd.read_excel(bio, sheet_name=None)
    dfs = []
    for sname, d in sheets.items():
        if d.empty:
            continue
        d.columns = d.columns.astype(str).str.strip()
        if not _has_required_cols(d.columns):
            found = False
            for i in range(min(20, len(d))):
                rv = [str(v).strip() for v in d.iloc[i].values]
                if _has_required_cols(rv):
                    d.columns = rv
                    d = d.iloc[i + 1:].reset_index(drop=True)
                    found = True
                    break
            if not found:
                continue
        d = d.dropna(how="all").reset_index(drop=True)
        d = _normalize_columns(d)
        if "Time" in d.columns and "Door Name" in d.columns:
            dfs.append(d)
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()


def process_access_logs(files_data: list) -> pd.DataFrame:
    """Parse and merge all access log files. Returns df_entry (first badge-in per person/day)."""
    all_dfs = [_load_file(f) for f in files_data]
    all_dfs = [d for d in all_dfs if not d.empty and "Time" in d.columns]
    if not all_dfs:
        raise ValueError("No valid log data found in uploaded files.")

    df = pd.concat(all_dfs, ignore_index=True)

    df["Parsed_Time"] = pd.to_datetime(df["Time"], errors="coerce", dayfirst=True)
    nat_mask = df["Parsed_Time"].isna()
    if nat_mask.any():
        df.loc[nat_mask, "Parsed_Time"] = pd.to_datetime(
            df.loc[nat_mask, "Time"], errors="coerce", dayfirst=False)
    df = df.dropna(subset=["Parsed_Time"]).copy()

    df["Event Description"] = df["Event Description"].astype(str).str.strip()
    df["Door Name"]         = df["Door Name"].astype(str).str.strip()

    df_entry = df[
        df["Event Description"].str.lower().isin([e.lower() for e in TARGET_EVENTS]) &
        df["Door Name"].str.lower().isin([d.lower() for d in TARGET_DOORS])
    ].copy()

    df_entry["Date"]      = df_entry["Parsed_Time"].dt.date
    df_entry["Time_Only"] = df_entry["Parsed_Time"].dt.time
    df_entry["Date_dt"]   = pd.to_datetime(df_entry["Date"])

    df_entry = df_entry.sort_values("Parsed_Time")
    df_first = df_entry.drop_duplicates(
        subset=["Date", "Personnel ID"], keep="first"
    ).copy()
    return df_first


def _load_roster(roster_info: dict):
    """Returns (df_std_roster, soc_ids_from_roster) or (None, set())."""
    if not roster_info:
        return None, set()
    bio = BytesIO(roster_info["data"])
    name = roster_info["name"]
    df = pd.read_csv(bio) if name.lower().endswith(".csv") else pd.read_excel(bio)
    df.columns = df.columns.astype(str).str.strip()

    col_map = {}
    for c in df.columns:
        cl = c.lower()
        if "personnel" in cl or cl == "id":
            col_map[c] = "Personnel ID"
        elif "expected" in cl or "days" in cl:
            col_map[c] = "Expected Days"
    df = df.rename(columns=col_map)

    if "Personnel ID" not in df.columns or "Expected Days" not in df.columns:
        return None, set()

    df["Personnel ID"]  = df["Personnel ID"].astype(str).str.strip()
    df["Expected Days"] = df["Expected Days"].astype(str).str.strip()

    soc_mask = df["Expected Days"].str.upper() == "SOC"
    soc_ids  = set(df.loc[soc_mask, "Personnel ID"].unique())
    df_std   = df[~soc_mask].copy()
    df_std["Days_Per_Week"] = pd.to_numeric(df_std["Expected Days"], errors="coerce")
    df_std = df_std.dropna(subset=["Days_Per_Week"]).copy()
    df_std["Days_Per_Week"] = df_std["Days_Per_Week"].astype(int)
    return df_std, soc_ids


def _load_soc(soc_info: dict):
    if not soc_info:
        return None
    bio  = BytesIO(soc_info["data"])
    name = soc_info["name"]
    df   = pd.read_csv(bio) if name.lower().endswith(".csv") else pd.read_excel(bio)
    df.columns = df.columns.astype(str).str.strip()
    df = _normalize_columns(df)

    for needed in ["Personnel ID", "Date", "Shift"]:
        if needed not in df.columns:
            return None

    df["Date"]        = pd.to_datetime(df["Date"], errors="coerce", dayfirst=True).dt.date
    df                = df.dropna(subset=["Date"]).copy()
    df["Shift_Lower"] = df["Shift"].astype(str).str.strip().str.lower()
    df["Shift_Start"] = df["Shift_Lower"].map(SOC_SHIFT_TIMES)
    df["Personnel ID"]= df["Personnel ID"].astype(str).str.strip()

    fn_cols = [c for c in ["First Name", "Last Name"] if c in df.columns]
    df["Full Name"] = df[fn_cols].fillna("").astype(str).apply(
        lambda r: " ".join(r).strip(), axis=1
    ) if fn_cols else ""
    return df


def compute_late_standard(df_first: pd.DataFrame, roster_info=None) -> dict:
    df_std_roster, soc_ids_from_roster = _load_roster(roster_info)

    soc_ids = soc_ids_from_roster.copy()
    df_std  = df_first[~df_first["Personnel ID"].astype(str).str.strip().isin(soc_ids)].copy()

    df_workday = df_std[df_std["Date_dt"].dt.dayofweek.isin(WORKDAYS)].copy()
    df_late    = df_workday[df_workday["Time_Only"] >= CUTOFF].copy()

    name_cols = [c for c in ["First Name", "Last Name"] if c in df_late.columns]
    df_late["Full Name"]  = df_late[name_cols].fillna("").astype(str).apply(
        lambda r: " ".join(r).strip(), axis=1) if name_cols else ""
    df_late["Date_Str"]   = df_late["Date"].apply(lambda d: d.strftime("%Y-%m-%d"))
    df_late["Time_Str"]   = df_late["Time_Only"].apply(lambda t: t.strftime("%H:%M:%S"))
    df_late["ISO_Week"]   = (
        df_late["Parsed_Time"].dt.isocalendar().year.astype(str) + "-W" +
        df_late["Parsed_Time"].dt.isocalendar().week.astype(str).str.zfill(2)
    )

    late_agg = pd.DataFrame()
    if not df_late.empty:
        late_agg = (
            df_late.sort_values(["Date", "Time_Only"])
            .groupby(["Personnel ID", "Full Name"])
            .agg(
                Days_Late=("Date", "nunique"),
                Weeks_Defaulted=("ISO_Week", "nunique"),
                Dates_Late=("Date_Str", lambda x: ", ".join(x)),
                Times_In=("Time_Str", lambda x: ", ".join(x)),
            )
            .reset_index()
            .sort_values("Days_Late", ascending=False)
        )
        if df_std_roster is not None:
            late_agg = late_agg.merge(
                df_std_roster[["Personnel ID", "Days_Per_Week"]],
                on="Personnel ID", how="left"
            )
            late_agg["Days_Per_Week"] = late_agg["Days_Per_Week"].fillna("–")
        else:
            late_agg["Days_Per_Week"] = "–"

    # Weekly compliance
    compliance_rows = []
    if df_std_roster is not None and not df_std.empty:
        df_std_att = df_std.copy()
        df_std_att["Personnel ID"] = df_std_att["Personnel ID"].astype(str).str.strip()
        df_std_att["ISO_Week"] = (
            df_std_att["Parsed_Time"].dt.isocalendar().year.astype(str) + "-W" +
            df_std_att["Parsed_Time"].dt.isocalendar().week.astype(str).str.zfill(2)
        )
        actual = (
            df_std_att.groupby(["Personnel ID", "ISO_Week"])
            .agg(Actual_Days=("Date", "nunique"))
            .reset_index()
        )

        min_dt = df_std_att["Parsed_Time"].min()
        max_dt = df_std_att["Parsed_Time"].max()
        all_weeks = pd.date_range(min_dt, max_dt, freq="W-MON")
        week_labels = []
        for w in all_weeks:
            iso = w.isocalendar()
            week_labels.append(f"{iso[0]}-W{str(iso[1]).zfill(2)}")
        if not week_labels:
            iso = min_dt.isocalendar()
            week_labels = [f"{iso[0]}-W{str(iso[1]).zfill(2)}"]

        cross = pd.MultiIndex.from_product(
            [df_std_roster["Personnel ID"].unique(), week_labels],
            names=["Personnel ID", "ISO_Week"]
        ).to_frame(index=False)
        cross = cross.merge(
            df_std_roster[["Personnel ID", "Days_Per_Week"]], on="Personnel ID", how="left"
        )
        comp = cross.merge(actual, on=["Personnel ID", "ISO_Week"], how="left")
        comp["Actual_Days"] = comp["Actual_Days"].fillna(0).astype(int)
        comp["Deficit"]     = comp["Days_Per_Week"] - comp["Actual_Days"]
        non_comp = comp[comp["Deficit"] > 0].copy()
        if not non_comp.empty:
            compliance_rows = non_comp.rename(columns={
                "ISO_Week": "Week", "Days_Per_Week": "Expected", "Actual_Days": "Actual"
            })[["Personnel ID", "Week", "Expected", "Actual", "Deficit"]].to_dict(orient="records")

    return {
        "late_count":     len(df_late),
        "late_records":   late_agg.to_dict(orient="records") if not late_agg.empty else [],
        "compliance":     compliance_rows,
        "roster_loaded":  df_std_roster is not None,
    }


def compute_soc_late_absent(df_first: pd.DataFrame, soc_info=None) -> dict:
    df_soc = _load_soc(soc_info)
    if df_soc is None:
        return {"soc_loaded": False}

    soc_pids = df_soc["Personnel ID"].unique()
    df_logs  = df_first[df_first["Personnel ID"].astype(str).str.strip().isin(soc_pids)].copy()
    df_logs["Personnel ID"] = df_logs["Personnel ID"].astype(str).str.strip()

    merged = df_soc.merge(
        df_logs[["Personnel ID", "Date", "Time_Only", "Parsed_Time"]],
        on=["Personnel ID", "Date"], how="left"
    )

    # Late
    present = merged.dropna(subset=["Time_Only"]).copy()
    present["Is_Late"] = present.apply(
        lambda r: r["Time_Only"] > r["Shift_Start"] if r["Shift_Start"] else False, axis=1)
    present["Minutes_Late"] = present.apply(
        lambda r: int((datetime.datetime.combine(r["Date"], r["Time_Only"]) -
                       datetime.datetime.combine(r["Date"], r["Shift_Start"])).total_seconds() // 60)
        if r["Is_Late"] and r["Shift_Start"] else 0, axis=1)

    soc_late = present[present["Is_Late"]].copy()
    soc_late["Date_Str"]       = soc_late["Date"].apply(lambda d: d.strftime("%Y-%m-%d"))
    soc_late["Shift_Start_Str"]= soc_late["Shift_Start"].apply(lambda t: t.strftime("%H:%M") if pd.notna(t) else "")
    soc_late["Time_In_Str"]    = soc_late["Time_Only"].apply(lambda t: t.strftime("%H:%M:%S"))

    late_agg = pd.DataFrame()
    if not soc_late.empty:
        late_agg = (
            soc_late.sort_values("Date")
            .groupby(["Personnel ID", "Full Name"])
            .agg(
                Late_Count=("Date", "nunique"),
                Dates_Late=("Date_Str", lambda x: ", ".join(x)),
                Shifts=("Shift", lambda x: ", ".join(x)),
                Scheduled_Start=("Shift_Start_Str", lambda x: ", ".join(x)),
                Time_In=("Time_In_Str", lambda x: ", ".join(x)),
                Total_Mins_Late=("Minutes_Late", "sum"),
            )
            .reset_index()
            .sort_values("Late_Count", ascending=False)
        )

    # Absent
    soc_absent = merged[merged["Time_Only"].isna()].copy()
    soc_absent["Date_Str"] = soc_absent["Date"].apply(lambda d: d.strftime("%Y-%m-%d"))

    absent_agg = pd.DataFrame()
    if not soc_absent.empty:
        absent_agg = (
            soc_absent.sort_values("Date")
            .groupby(["Personnel ID", "Full Name"])
            .agg(
                Absent_Count=("Date", "nunique"),
                Dates_Absent=("Date_Str", lambda x: ", ".join(x)),
                Shifts=("Shift", lambda x: ", ".join(x)),
            )
            .reset_index()
            .sort_values("Absent_Count", ascending=False)
        )

    return {
        "soc_loaded":    True,
        "late_count":    len(soc_late),
        "late_records":  late_agg.to_dict(orient="records") if not late_agg.empty else [],
        "absent_count":  len(soc_absent),
        "absent_records":absent_agg.to_dict(orient="records") if not absent_agg.empty else [],
    }


def export_report(data: dict, report_type: str = "late") -> BytesIO:
    buf = BytesIO()
    rows = data.get("records", [])
    if not rows:
        df = pd.DataFrame({"Note": ["No data to export"]})
    else:
        df = pd.DataFrame(rows)
    with pd.ExcelWriter(buf, engine="xlsxwriter") as w:
        df.to_excel(w, index=False, sheet_name=report_type[:31])
    buf.seek(0)
    return buf
