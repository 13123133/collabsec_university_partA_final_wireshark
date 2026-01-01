from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import streamlit as st

from modules.storage import JsonStore, DataFiles
from modules.security import hash_password, verify_password
from modules.pcap_analyzer import extract_indicators, match_ip_iocs, HAS_SCAPY
from modules.wireshark_csv import parse_wireshark_csv, analyze_rows


# ============================================================
# University App Config
# ============================================================
APP_TITLE = "Cybersecurity Collaboration Portal (University)"
APP_TAGLINE = "Cross-Sector Cybersecurity Collaboration Model — University Campus Scenario"

ROLES = ["dept_rep", "analyst", "admin"]
ROLE_LABEL = {
    "dept_rep": "Department Representative",
    "analyst": "SOC Analyst",
    "admin": "Security Team Admin",
}
ROLE_RANK = {"dept_rep": 0, "analyst": 1, "admin": 2}

DEPARTMENTS = ["SEC", "IT", "LIB", "ADM", "HEALTH", "FAC"]
DEPT_LABEL = {
    "SEC": "Security Team",
    "IT": "IT Services",
    "LIB": "Library",
    "ADM": "Administration",
    "HEALTH": "Health Services",
    "FAC": "Faculty / Academic",
}

SEVERITIES = ["low", "medium", "high", "critical"]
IOC_TYPES = ["ip", "domain", "url", "hash"]
INC_STATUSES = ["open", "investigating", "resolved"]

# Storage locations
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
TMP_DIR = os.path.join(BASE_DIR, "tmp")

files = DataFiles()
store = JsonStore(DATA_DIR)


# ============================================================
# Helpers
# ============================================================
def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def ensure_data_files() -> None:
    for fn in [files.users, files.iocs, files.incidents, files.audit, files.notifications]:
        store.ensure_file(fn)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(TMP_DIR, exist_ok=True)


def role_ok(user: dict, min_role: str) -> bool:
    return ROLE_RANK.get(str(user.get("role")), 0) >= ROLE_RANK.get(min_role, 0)


def dept_name(code: str) -> str:
    return DEPT_LABEL.get(code, code)


def role_name(code: str) -> str:
    return ROLE_LABEL.get(code, code)


def get_user() -> Optional[dict]:
    return st.session_state.get("user")


def require_login() -> dict:
    u = get_user()
    if not u:
        st.warning("Please login first.")
        st.stop()
    return u


def require_role(min_role: str) -> dict:
    u = require_login()
    if not role_ok(u, min_role):
        st.error("You do not have permission to access this page.")
        st.stop()
    return u


def audit(action: str, actor: Optional[dict], details: dict) -> None:
    logs = store.read_list(files.audit)
    logs.append(
        {
            "id": str(uuid.uuid4()),
            "ts": now_iso(),
            "action": action,
            "actor": {
                "id": (actor or {}).get("id"),
                "username": (actor or {}).get("username"),
                "role": (actor or {}).get("role"),
                "department": (actor or {}).get("department"),
            },
            "details": details,
        }
    )
    store.write_list(files.audit, logs)


def push_notification(dept_code: str, title: str, message: str, related_incident_id: Optional[str] = None) -> None:
    notifs = store.read_list(files.notifications)
    notifs.append(
        {
            "id": str(uuid.uuid4()),
            "ts": now_iso(),
            "department": dept_code,
            "title": title,
            "message": message,
            "incident_id": related_incident_id,
            "read": False,
        }
    )
    store.write_list(files.notifications, notifs)


def mark_dept_notifications_read(dept_code: str) -> None:
    notifs = store.read_list(files.notifications)
    changed = False
    for n in notifs:
        if n.get("department") == dept_code and not n.get("read", False):
            n["read"] = True
            changed = True
    if changed:
        store.write_list(files.notifications, notifs)


def users_all() -> List[dict]:
    users = store.read_list(files.users)
    for u in users:
        u.setdefault("role", "dept_rep")
        u.setdefault("department", "IT")
        u.setdefault("active", True)
        u.setdefault("created_at", now_iso())
    return users


def save_users(users: List[dict]) -> None:
    store.write_list(files.users, users)


def find_user_by_username(username: str) -> Optional[dict]:
    username = str(username or "").strip().lower()
    for u in users_all():
        if str(u.get("username", "")).strip().lower() == username:
            return u
    return None


def set_session_user(record: dict) -> None:
    st.session_state["user"] = {
        "id": record["id"],
        "username": record["username"],
        "role": record.get("role", "dept_rep"),
        "department": record.get("department", "IT"),
    }


def logout() -> None:
    st.session_state["user"] = None
    st.rerun()


def has_any_users() -> bool:
    return len(store.read_list(files.users)) > 0


# ============================================================
# Incident access rules
# ============================================================
def incident_involves_dept(inc: dict, dept: str) -> bool:
    if inc.get("affected_department") == dept:
        return True
    if inc.get("assigned_department") == dept:
        return True
    if dept in (inc.get("collaborator_departments") or []):
        return True
    return False


def can_view_incident(user: dict, inc: dict) -> bool:
    if role_ok(user, "analyst"):
        return True
    return incident_involves_dept(inc, str(user.get("department")))


def can_update_incident(user: dict, inc: dict) -> bool:
    if role_ok(user, "analyst"):
        return True
    return incident_involves_dept(inc, str(user.get("department")))


# ============================================================
# Sidebar
# ============================================================
def render_sidebar() -> str:
    u = get_user()
    if u:
        st.sidebar.success(
            f"{u.get('username')} • {role_name(str(u.get('role')))} • {dept_name(str(u.get('department')))}"
        )
        if st.sidebar.button("Logout", key="sb_logout"):
            logout()
    else:
        st.sidebar.info("Not logged in")

    st.sidebar.caption(APP_TAGLINE)

    if not has_any_users():
        return st.sidebar.radio("Navigation", ["Initial Setup"], index=0, key="nav_setup")

    if not u:
        return st.sidebar.radio("Navigation", ["Login"], index=0, key="nav_login")

    items = ["Dashboard", "Threat Intel", "Incidents", "PCAP Analyzer"]
    if role_ok(u, "admin"):
        items += ["Audit Log", "Admin"]
    return st.sidebar.radio("Navigation", items, index=0, key="nav_main")


# ============================================================
# Pages
# ============================================================
def page_initial_setup() -> None:
    st.header("Initial Setup (Create First Admin)")
    st.info("Setup appears only when there are no users. Create the first Security Team admin account.")

    with st.form("setup_form"):
        username = st.text_input("Admin username", value="admin", key="setup_user")
        password = st.text_input("Admin password (>=8 chars)", type="password", key="setup_pw")
        password2 = st.text_input("Confirm password", type="password", key="setup_pw2")
        submitted = st.form_submit_button("Create Admin")

    if submitted:
        username = username.strip()
        if len(username) < 3:
            st.error("Username must be at least 3 characters.")
            return
        if len(password) < 8:
            st.error("Password must be at least 8 characters.")
            return
        if password != password2:
            st.error("Password confirmation does not match.")
            return
        if has_any_users():
            st.error("Users already exist. Setup is disabled.")
            return

        rec = {
            "id": str(uuid.uuid4()),
            "username": username,
            "password_hash": hash_password(password),
            "role": "admin",
            "department": "SEC",
            "active": True,
            "created_at": now_iso(),
        }
        store.write_list(files.users, [rec])
        set_session_user(rec)
        audit("setup_admin_created", get_user(), {"username": username})
        st.success("Admin created successfully.")
        st.rerun()


def page_login() -> None:
    st.header("Login")

    with st.form("login_form"):
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pw")
        submitted = st.form_submit_button("Login")

    if not submitted:
        return

    record = find_user_by_username(username)
    if not record:
        st.error("Invalid username/password.")
        audit("login_failed", None, {"reason": "user_not_found", "username": username})
        return
    if not bool(record.get("active", True)):
        st.error("Account disabled. Contact Security Team.")
        audit("login_failed", None, {"reason": "inactive", "username": record.get("username")})
        return
    if not verify_password(password, str(record.get("password_hash", ""))):
        st.error("Invalid username/password.")
        audit("login_failed", None, {"reason": "bad_password", "username": record.get("username")})
        return

    set_session_user(record)
    audit("login_success", get_user(), {})
    st.success("Login successful.")
    st.rerun()


def page_dashboard() -> None:
    u = require_login()
    st.header("Dashboard")

    iocs = store.read_list(files.iocs)
    incs_all = store.read_list(files.incidents)
    incs = [x for x in incs_all if can_view_incident(u, x)]

    notifs = store.read_list(files.notifications)
    my_notifs = [n for n in notifs if n.get("department") == u.get("department") and not n.get("read", False)]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("IOCs (campus)", len(iocs))
    c2.metric("Incidents (visible)", len(incs))
    c3.metric("Open incidents", sum(1 for x in incs if x.get("status") == "open"))
    c4.metric("New notifications", len(my_notifs))

    if my_notifs:
        with st.expander("Notifications", expanded=True):
            for n in sorted(my_notifs, key=lambda x: x.get("ts", ""), reverse=True)[:10]:
                st.write(f"- **{n.get('title')}** — {n.get('message')}  \n  _{n.get('ts')}_")
            if st.button("Mark all as read", key="mark_notifs_read"):
                mark_dept_notifications_read(str(u.get("department")))
                audit("notifications_mark_read", u, {"department": u.get("department")})
                st.rerun()

    st.subheader("Recent IOCs")
    recent_iocs = sorted(iocs, key=lambda x: x.get("created_at", ""), reverse=True)[:6]
    if not recent_iocs:
        st.info("No IOC records yet.")
    else:
        for r in recent_iocs:
            st.write(
                f"- [{r.get('severity')}] {r.get('ioc_type')} = `{r.get('value')}` • {dept_name(str(r.get('department')))}"
            )

    st.subheader("Recent Incidents (visible)")
    recent_incs = sorted(incs, key=lambda x: x.get("created_at", ""), reverse=True)[:6]
    if not recent_incs:
        st.info("No incidents yet.")
    else:
        for r in recent_incs:
            st.write(
                f"- [{r.get('severity')}] {r.get('status')} — {r.get('title')} • affected: {dept_name(str(r.get('affected_department')))}"
            )


def page_threat_intel() -> None:
    u = require_login()
    st.header("Threat Intelligence (IOC Board)")
    st.caption("Campus-wide IOC sharing to support coordinated response.")

    can_submit = role_ok(u, "analyst") or role_ok(u, "admin")

    if not can_submit:
        st.info("You can view IOCs. Only Analyst/Admin can submit new IOCs.")

    with st.expander("Add IOC", expanded=can_submit):
        if can_submit:
            with st.form("ioc_form"):
                ioc_type = st.selectbox("IOC Type", IOC_TYPES, key="ioc_type")
                value = st.text_input(
                    "Value",
                    placeholder="e.g., 1.2.3.4 / example.com / https://... / hash",
                    key="ioc_value",
                )
                severity = st.selectbox("Severity", SEVERITIES, index=1, key="ioc_sev")
                confidence = st.slider("Confidence", 1, 100, 70, key="ioc_conf")
                tags = st.text_input("Tags (comma separated)", placeholder="phishing, scan, ransomware", key="ioc_tags")
                source = st.selectbox("Source", ["manual", "pcap_match", "threat_feed"], key="ioc_source")
                note = st.text_area("Note", height=90, key="ioc_note")
                submitted = st.form_submit_button("Submit IOC")

            if submitted:
                v = value.strip()
                if len(v) < 3:
                    st.error("Value too short.")
                    return

                rec = {
                    "id": str(uuid.uuid4()),
                    "ioc_type": ioc_type,
                    "value": v,
                    "severity": severity,
                    "confidence": int(confidence),
                    "tags": [t.strip() for t in tags.split(",") if t.strip()],
                    "source": source,
                    "note": note.strip() if note else None,
                    "status": "active",
                    "department": u.get("department"),
                    "created_by": u.get("id"),
                    "created_by_username": u.get("username"),
                    "created_at": now_iso(),
                    "last_seen": now_iso(),
                }
                iocs = store.read_list(files.iocs)
                iocs.append(rec)
                store.write_list(files.iocs, iocs)
                audit("ioc_created", u, {"ioc_type": ioc_type, "value": v})
                st.success("IOC submitted.")
                st.rerun()

    st.subheader("IOC List")
    iocs = store.read_list(files.iocs)
    if not iocs:
        st.info("No IOCs yet.")
        return

    col1, col2, col3 = st.columns(3)
    with col1:
        f_type = st.selectbox("Filter type", ["(all)"] + IOC_TYPES, key="f_ioc_type")
    with col2:
        f_sev = st.selectbox("Filter severity", ["(all)"] + SEVERITIES, key="f_ioc_sev")
    with col3:
        f_dept = st.selectbox(
            "Filter department",
            ["(all)"] + DEPARTMENTS,
            format_func=dept_name,
            key="f_ioc_dept",
        )

    q = st.text_input("Search (value / tag / note)", key="ioc_search").strip().lower()

    filtered = iocs
    if f_type != "(all)":
        filtered = [x for x in filtered if x.get("ioc_type") == f_type]
    if f_sev != "(all)":
        filtered = [x for x in filtered if x.get("severity") == f_sev]
    if f_dept != "(all)":
        filtered = [x for x in filtered if x.get("department") == f_dept]
    if q:

        def match(x: dict) -> bool:
            blob = " ".join(
                [
                    str(x.get("value", "")),
                    " ".join(x.get("tags") or []),
                    str(x.get("note", "")),
                ]
            ).lower()
            return q in blob

        filtered = [x for x in filtered if match(x)]

    view = []
    for r in sorted(filtered, key=lambda x: x.get("created_at", ""), reverse=True):
        view.append(
            {
                "type": r.get("ioc_type"),
                "value": r.get("value"),
                "severity": r.get("severity"),
                "confidence": r.get("confidence"),
                "department": dept_name(str(r.get("department"))),
                "tags": ", ".join(r.get("tags") or []),
                "source": r.get("source"),
                "status": r.get("status"),
                "created_at": r.get("created_at"),
            }
        )
    st.dataframe(view, use_container_width=True, hide_index=True)


def incident_upload_path(incident_id: str) -> str:
    p = os.path.join(UPLOAD_DIR, incident_id)
    os.makedirs(p, exist_ok=True)
    return p


def page_incidents() -> None:
    u = require_login()
    st.header("Incidents (Incident Response)")
    st.caption("Cross-department reporting, coordination, and secure communication (comments + audit).")

    # ---------- Create Incident ----------
    with st.expander("Create Incident", expanded=True):
        with st.form("inc_create_form"):
            title = st.text_input("Title", key="inc_title")
            description = st.text_area("Description", height=120, key="inc_desc")
            severity = st.selectbox("Severity", SEVERITIES, index=1, key="inc_sev")
            affected_dept = st.selectbox(
                "Affected Department", DEPARTMENTS, format_func=dept_name, key="inc_aff_dept"
            )
            assigned_dept = st.selectbox(
                "Assigned Department (triage)",
                DEPARTMENTS,
                format_func=dept_name,
                index=DEPARTMENTS.index("SEC"),
                key="inc_asg_dept",
            )
            collaborators = st.multiselect(
                "Collaborator Departments", DEPARTMENTS, format_func=dept_name, key="inc_collab"
            )
            submitted = st.form_submit_button("Create")

        if submitted:
            t = title.strip()
            d = description.strip()
            if len(t) < 5 or len(d) < 10:
                st.error("Title >= 5 chars, Description >= 10 chars.")
                return

            incs = store.read_list(files.incidents)
            rid = str(uuid.uuid4())
            ts = now_iso()

            inc = {
                "id": rid,
                "title": t,
                "description": d,
                "severity": severity,
                "status": "open",
                "affected_department": affected_dept,
                "assigned_department": assigned_dept,
                "collaborator_departments": list(dict.fromkeys(collaborators)),
                "created_by": u.get("id"),
                "created_by_username": u.get("username"),
                "created_by_department": u.get("department"),
                "created_at": ts,
                "updated_at": ts,
                "comments": [],
                "evidence": [],
                "timeline": [{"ts": ts, "by": u.get("username"), "action": "created", "note": None}],
            }

            incs.append(inc)
            store.write_list(files.incidents, incs)
            audit("incident_created", u, {"incident_id": rid, "affected": affected_dept, "assigned": assigned_dept})

            involved: Set[str] = set([affected_dept, assigned_dept] + inc.get("collaborator_departments", []))
            for dept in involved:
                push_notification(dept, "New Incident", f"{t} (severity: {severity})", related_incident_id=rid)

            st.success("Incident created.")
            st.rerun()

    # ---------- List & Filter ----------
    incs_all = store.read_list(files.incidents)
    incs_visible = [x for x in incs_all if can_view_incident(u, x)]

    if not incs_visible:
        st.info("No incidents visible yet.")
        return

    col1, col2, col3 = st.columns(3)
    with col1:
        f_status = st.selectbox("Filter status", ["(all)"] + INC_STATUSES, key="inc_f_status")
    with col2:
        f_dept = st.selectbox(
            "Filter affected dept", ["(all)"] + DEPARTMENTS, format_func=dept_name, key="inc_f_dept"
        )
    with col3:
        f_sev = st.selectbox("Filter severity", ["(all)"] + SEVERITIES, key="inc_f_sev")

    filtered = incs_visible
    if f_status != "(all)":
        filtered = [x for x in filtered if x.get("status") == f_status]
    if f_dept != "(all)":
        filtered = [x for x in filtered if x.get("affected_department") == f_dept]
    if f_sev != "(all)":
        filtered = [x for x in filtered if x.get("severity") == f_sev]

    def label(x: dict) -> str:
        return f"{x['id'][:8]} • {x.get('status')} • [{x.get('severity')}] {x.get('title')}"

    options = {label(x): x["id"] for x in sorted(filtered, key=lambda x: x.get("created_at", ""), reverse=True)}
    chosen = st.selectbox("Select incident", list(options.keys()), key="inc_select")
    inc_id = options[chosen]
    inc = next(x for x in incs_all if x["id"] == inc_id)

    # ---------- View ----------
    st.subheader("Incident Details")
    st.write(
        f"**Affected:** {dept_name(str(inc.get('affected_department')))}  |  "
        f"**Assigned:** {dept_name(str(inc.get('assigned_department')))}  |  "
        f"**Collaborators:** {', '.join(dept_name(d) for d in (inc.get('collaborator_departments') or [])) or '-'}"
    )
    st.write(f"**Created by:** {inc.get('created_by_username')} ({dept_name(str(inc.get('created_by_department')))})")
    st.write(f"**Created at:** {inc.get('created_at')}  |  **Updated at:** {inc.get('updated_at')}")
    st.write("**Description**")
    st.write(inc.get("description"))

    # ---------- Update (status/assignment) ----------
    st.subheader("Update Incident")
    if not can_update_incident(u, inc):
        st.info("You can view this incident but do not have permission to update it.")
    else:
        with st.form(f"inc_update_form_{inc_id}"):
            new_status = st.selectbox(
                "Status",
                INC_STATUSES,
                index=INC_STATUSES.index(inc.get("status", "open")),
                key=f"inc_status_{inc_id}",
            )
            new_assigned = st.selectbox(
                "Assigned Department",
                DEPARTMENTS,
                format_func=dept_name,
                index=DEPARTMENTS.index(str(inc.get("assigned_department", "SEC")))
                if str(inc.get("assigned_department", "SEC")) in DEPARTMENTS
                else 0,
                key=f"inc_asg_{inc_id}",
            )
            new_collab = st.multiselect(
                "Collaborator Departments",
                DEPARTMENTS,
                format_func=dept_name,
                default=list(inc.get("collaborator_departments") or []),
                key=f"inc_col_{inc_id}",
            )
            note = st.text_input("Update note (optional)", key=f"inc_note_{inc_id}")
            submitted = st.form_submit_button("Apply update")

        if submitted:
            before = {
                "status": inc.get("status"),
                "assigned": inc.get("assigned_department"),
                "collab": inc.get("collaborator_departments"),
            }
            inc["status"] = new_status
            inc["assigned_department"] = new_assigned
            inc["collaborator_departments"] = list(dict.fromkeys(new_collab))
            inc["updated_at"] = now_iso()
            inc.setdefault("timeline", []).append(
                {"ts": inc["updated_at"], "by": u.get("username"), "action": "updated", "note": note.strip() if note else None}
            )

            store.write_list(files.incidents, incs_all)
            audit(
                "incident_updated",
                u,
                {
                    "incident_id": inc_id,
                    "before": before,
                    "after": {"status": new_status, "assigned": new_assigned, "collab": inc["collaborator_departments"]},
                },
            )

            involved: Set[str] = set(
                [inc.get("affected_department"), inc.get("assigned_department")] + (inc.get("collaborator_departments") or [])
            )
            involved.discard(None)  # type: ignore[arg-type]
            for dept in involved:
                push_notification(str(dept), "Incident Updated", f"{inc.get('title')} → {new_status}", related_incident_id=inc_id)

            st.success("Updated.")
            st.rerun()

    # ---------- Secure communication: Comments ----------
    st.subheader("Comments (Secure Communication)")
    comments = inc.get("comments") or []
    if not comments:
        st.info("No comments yet.")
    else:
        for c in sorted(comments, key=lambda x: x.get("ts", "")):
            st.write(f"- **{c.get('by')}** ({dept_name(str(c.get('department')))}) @ {c.get('ts')}")
            st.write(f"  {c.get('text')}")
            st.write("")

    with st.form(f"comment_form_{inc_id}"):
        text = st.text_area("Add a comment", height=90, key=f"comment_text_{inc_id}")
        submitted = st.form_submit_button("Post comment")
    if submitted:
        txt = text.strip()
        if len(txt) < 3:
            st.error("Comment too short.")
        else:
            inc.setdefault("comments", []).append(
                {"id": str(uuid.uuid4()), "ts": now_iso(), "by": u.get("username"), "department": u.get("department"), "text": txt}
            )
            inc["updated_at"] = now_iso()
            inc.setdefault("timeline", []).append({"ts": inc["updated_at"], "by": u.get("username"), "action": "commented", "note": None})
            store.write_list(files.incidents, incs_all)
            audit("incident_comment", u, {"incident_id": inc_id})

            involved: Set[str] = set(
                [inc.get("affected_department"), inc.get("assigned_department")] + (inc.get("collaborator_departments") or [])
            )
            involved.discard(u.get("department"))
            for dept in involved:
                push_notification(str(dept), "New Comment", f"{inc.get('title')} — new comment", related_incident_id=inc_id)

            st.success("Comment posted.")
            st.rerun()

    # ---------- Evidence upload ----------
    st.subheader("Evidence Upload")
    st.caption("Upload supporting evidence (pcap/log/screenshot). Stored locally (prototype).")

    upload = st.file_uploader(
        "Upload file",
        type=["pcap", "log", "txt", "csv", "png", "jpg", "jpeg", "pdf"],
        key=f"evi_up_{inc_id}",
    )

    if upload is not None:
        save_dir = incident_upload_path(inc_id)
        safe_name = f"{uuid.uuid4()}_{upload.name}"
        save_path = os.path.join(save_dir, safe_name)
        with open(save_path, "wb") as f:
            f.write(upload.getbuffer())

        meta = {
            "id": str(uuid.uuid4()),
            "ts": now_iso(),
            "filename": upload.name,
            "stored_as": safe_name,
            "path": save_path,
            "uploaded_by": u.get("username"),
            "department": u.get("department"),
        }
        inc.setdefault("evidence", []).append(meta)
        inc["updated_at"] = now_iso()
        inc.setdefault("timeline", []).append({"ts": inc["updated_at"], "by": u.get("username"), "action": "uploaded_evidence", "note": upload.name})
        store.write_list(files.incidents, incs_all)
        audit("incident_evidence_upload", u, {"incident_id": inc_id, "filename": upload.name})
        st.success("Evidence uploaded.")
        st.rerun()

    evidence = inc.get("evidence") or []
    if evidence:
        for e in sorted(evidence, key=lambda x: x.get("ts", ""), reverse=True):
            st.write(f"- {e.get('filename')} • by {e.get('uploaded_by')} ({dept_name(str(e.get('department')))}) @ {e.get('ts')}")
            try:
                with open(e.get("path"), "rb") as f:
                    data = f.read()
                st.download_button(
                    label=f"Download: {e.get('filename')}",
                    data=data,
                    file_name=e.get("filename"),
                    key=f"dl_{inc_id}_{e.get('id')}",
                )
            except Exception:
                st.warning("File not readable (moved/deleted).")

    # ---------- Mini summary table ----------
    st.divider()
    st.subheader("Incidents Table (visible)")
    table = []
    for x in sorted(incs_visible, key=lambda r: r.get("created_at", ""), reverse=True):
        table.append(
            {
                "id": x.get("id"),
                "title": x.get("title"),
                "severity": x.get("severity"),
                "status": x.get("status"),
                "affected": dept_name(str(x.get("affected_department"))),
                "assigned": dept_name(str(x.get("assigned_department"))),
                "updated_at": x.get("updated_at"),
            }
        )
    st.dataframe(table, use_container_width=True, hide_index=True)


def page_pcap() -> None:
    u = require_login()
    st.header("PCAP Analyzer")
    st.caption(
        "Two options: (A) Upload Wireshark CSV (works on Streamlit Cloud), or (B) Upload PCAP (requires Scapy)."
    )

    tab_csv, tab_pcap = st.tabs(["Wireshark CSV import (recommended)", "PCAP upload (Scapy)"])

    # ------------------------------
    # A) Wireshark CSV import
    # ------------------------------
    with tab_csv:
        st.subheader("A) Wireshark CSV import")
        st.caption(
            "Wireshark → File → Export Packet Dissections → As CSV... (Displayed). "
            "Then upload the CSV here to auto-generate IOC + Incident + Audit logs."
        )

        csv_up = st.file_uploader("Upload Wireshark CSV", type=["csv"], key="ws_csv_upload")
        if not csv_up:
            st.info("Upload a Wireshark-exported .csv to analyze.")
        else:
            rows = parse_wireshark_csv(csv_up.getvalue())
            if not rows:
                st.error("Could not parse this CSV. Export again using Wireshark 'Export Packet Dissections → As CSV'.")
                audit("wireshark_csv_parse_failed", u, {"filename": csv_up.name})
            else:
                summary = analyze_rows(rows)

                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Packets", summary.get("packets", 0))
                c2.metric("Unique src IPs", summary.get("unique_src_ips", 0))
                c3.metric("Unique dst IPs", summary.get("unique_dst_ips", 0))
                c4.metric("Dst ports (top flow)", summary.get("unique_dst_ports_top_flow", 0))

                st.write(
                    {
                        "top_attacker_ip": summary.get("top_attacker_ip"),
                        "top_target_ip": summary.get("top_target_ip"),
                        "open_ports_inferred": summary.get("open_ports_inferred"),
                        "scan_label": summary.get("label"),
                    }
                )

                with st.expander("Preview (first 30 rows)"):
                    st.dataframe(rows[:30], use_container_width=True, hide_index=True)

                if st.button("Generate IOC + Incident from CSV", key="ws_csv_generate"):
                    ts = now_iso()
                    iocs = store.read_list(files.iocs)
                    incs = store.read_list(files.incidents)

                    attacker = summary.get("top_attacker_ip")
                    target = summary.get("top_target_ip")
                    open_ports = summary.get("open_ports_inferred") or []

                    created_iocs = 0

                    def upsert_ioc(ioc_type: str, value: str, severity: str, confidence: str, tags: List[str]) -> None:
                        nonlocal created_iocs
                        if not value:
                            return
                        if any((x.get("ioc_type") == ioc_type and str(x.get("value")) == value) for x in iocs):
                            return
                        iocs.append(
                            {
                                "id": str(uuid.uuid4()),
                                "ioc_type": ioc_type,
                                "value": value,
                                "severity": severity,
                                "confidence": confidence,
                                "department": "SEC",
                                "source": "wireshark_csv",
                                "tags": tags,
                                "created_by": u.get("id"),
                                "created_by_username": u.get("username"),
                                "created_by_department": u.get("department"),
                                "created_at": ts,
                            }
                        )
                        created_iocs += 1

                    # IOCs
                    if attacker:
                        upsert_ioc("ip", str(attacker), "medium", "medium", ["port-scan", "lab"])  # attacker
                    if target:
                        upsert_ioc("ip", str(target), "low", "high", ["campus-host", "lab"])  # target
                    for p in open_ports:
                        upsert_ioc("port", f"tcp/{p}", "low", "medium", ["exposed-service", "lab"])

                    store.write_list(files.iocs, iocs)

                    # Incident
                    rid = str(uuid.uuid4())
                    title = f"{summary.get('label')} (Wireshark CSV)"
                    desc = (
                        f"Wireshark CSV analysis detected: {summary.get('label')}\n\n"
                        f"Attacker: {attacker}\n"
                        f"Target: {target}\n"
                        f"Destination ports (top flow): {summary.get('dst_ports_top_flow')}\n"
                        f"Inferred open ports (SYN,ACK): {open_ports}\n"
                        f"Packets: {summary.get('packets')}\n"
                    )

                    inc = {
                        "id": rid,
                        "title": title,
                        "description": desc,
                        "severity": "medium" if summary.get("unique_dst_ports_top_flow", 0) >= 5 else "low",
                        "status": "open",
                        "affected_department": "IT",  # victim host is typically IT service
                        "assigned_department": "SEC",
                        "collaborator_departments": ["IT"],
                        "created_by": u.get("id"),
                        "created_by_username": u.get("username"),
                        "created_by_department": u.get("department"),
                        "created_at": ts,
                        "updated_at": ts,
                        "comments": [],
                        "evidence": [
                            {
                                "ts": ts,
                                "type": "wireshark_csv",
                                "note": f"Uploaded: {csv_up.name}",
                            }
                        ],
                        "timeline": [
                            {
                                "ts": ts,
                                "by": u.get("username"),
                                "action": "created_from_wireshark_csv",
                                "note": None,
                            }
                        ],
                    }

                    incs.append(inc)
                    store.write_list(files.incidents, incs)

                    audit(
                        "wireshark_csv_import",
                        u,
                        {
                            "filename": csv_up.name,
                            "created_iocs": created_iocs,
                            "incident_id": rid,
                            "label": summary.get("label"),
                        },
                    )

                    for dept in {inc["affected_department"], inc["assigned_department"]}:
                        push_notification(str(dept), "New Incident (Wireshark CSV)", title, related_incident_id=rid)

                    st.success(f"Created {created_iocs} IOC(s) and 1 Incident.")
                    st.rerun()

    # ------------------------------
    # B) PCAP upload (Scapy)
    # ------------------------------
    with tab_pcap:
        st.subheader("B) PCAP upload (Scapy)")
        st.caption("Upload a PCAP → extract IPs → match against IP-type IOCs.")

        if not HAS_SCAPY:
            st.warning("Scapy is not available in this environment. Use the CSV import tab above.")
            return

        uploaded = st.file_uploader("Upload PCAP file", type=["pcap"], key="pcap_upload")
        max_packets = st.slider("Max packets to read", 200, 5000, 2000, step=200, key="pcap_max")

        if not uploaded:
            st.info("Upload a .pcap to analyze.")
            return

        tmp_path = os.path.join(TMP_DIR, f"{uuid.uuid4()}_{uploaded.name}")
        with open(tmp_path, "wb") as f:
            f.write(uploaded.getbuffer())

        try:
            extracted = extract_indicators(tmp_path, max_packets=int(max_packets))
        except Exception as e:
            st.error(f"Failed to parse PCAP: {e}")
            audit("pcap_parse_failed", u, {"error": str(e)})
            return

        unique_ips: List[str] = extracted["unique_ips"]  # type: ignore[assignment]
        st.subheader("Extraction Summary")
        c1, c2 = st.columns(2)
        c1.metric("Packets read", int(extracted["packet_count"]))  # type: ignore[arg-type]
        c2.metric("Unique IPs", len(unique_ips))
        st.write("Protocol counts:", extracted["protocol_counts"])

        with st.expander("Extracted IP list"):
            st.code("\n".join(unique_ips) if unique_ips else "(none)")

        iocs = store.read_list(files.iocs)
        hits = match_ip_iocs(unique_ips, iocs)

        st.subheader("IOC Match Results (IP-type)")
        if not hits:
            st.success("No matching IP IOCs found.")
            audit("pcap_ioc_match", u, {"hits": 0})
            return

        st.warning(f"Matched {len(hits)} IP IOC(s).")
        view_hits = []
        for h in hits:
            view_hits.append(
                {
                    "value": h.get("value"),
                    "severity": h.get("severity"),
                    "confidence": h.get("confidence"),
                    "department": dept_name(str(h.get("department"))),
                    "tags": ", ".join(h.get("tags") or []),
                    "source": h.get("source"),
                }
            )
        st.dataframe(view_hits, use_container_width=True, hide_index=True)
        audit("pcap_ioc_match", u, {"hits": len(hits)})

        if st.button("Create Incident from matches", key="pcap_make_inc"):
            incs = store.read_list(files.incidents)
            rid = str(uuid.uuid4())
            ts = now_iso()

            title = f"PCAP IOC Match ({len(hits)} hit(s))"
            desc = "Matched IOC(s):\n" + "\n".join([f"- ip={x.get('value')} ({x.get('severity')})" for x in hits[:20]])

            inc = {
                "id": rid,
                "title": title,
                "description": desc,
                "severity": "high" if any(x.get("severity") in ("high", "critical") for x in hits) else "medium",
                "status": "open",
                "affected_department": str(u.get("department")),
                "assigned_department": "SEC",
                "collaborator_departments": [],
                "created_by": u.get("id"),
                "created_by_username": u.get("username"),
                "created_by_department": u.get("department"),
                "created_at": ts,
                "updated_at": ts,
                "comments": [],
                "evidence": [],
                "timeline": [{"ts": ts, "by": u.get("username"), "action": "created_from_pcap", "note": None}],
            }

            incs.append(inc)
            store.write_list(files.incidents, incs)
            audit("incident_created_from_pcap", u, {"incident_id": rid, "hits": len(hits)})

            involved = set([inc["affected_department"], inc["assigned_department"]])
            for dept in involved:
                push_notification(str(dept), "New Incident (from PCAP)", title, related_incident_id=rid)

            st.success("Incident created.")
            st.rerun()


def page_audit_log() -> None:
    _ = require_role("admin")
    st.header("Audit Log")
    logs = store.read_list(files.audit)
    if not logs:
        st.info("No audit records yet.")
        return

    q = st.text_input("Search (action/username/department)", key="audit_search").strip().lower()

    filtered = logs
    if q:

        def match(x: dict) -> bool:
            actor = x.get("actor") or {}
            blob = " ".join([str(x.get("action", "")), str(actor.get("username", "")), str(actor.get("department", ""))]).lower()
            return q in blob

        filtered = [x for x in filtered if match(x)]

    show = []
    for x in sorted(filtered, key=lambda t: t.get("ts", ""), reverse=True)[:200]:
        actor = x.get("actor") or {}
        show.append(
            {
                "ts": x.get("ts"),
                "action": x.get("action"),
                "username": actor.get("username"),
                "role": actor.get("role"),
                "department": dept_name(str(actor.get("department"))),
                "details": x.get("details"),
            }
        )
    st.dataframe(show, use_container_width=True, hide_index=True)


def page_admin() -> None:
    u = require_role("admin")
    st.header("Admin — User Management")

    users = users_all()

    st.subheader("Create User (Admin only)")
    with st.form("admin_create_user"):
        nu = st.text_input("Username", key="adm_nu")
        npw = st.text_input("Password (>=8 chars)", type="password", key="adm_npw")
        role = st.selectbox("Role", ROLES, format_func=role_name, key="adm_role")
        dept = st.selectbox("Department", DEPARTMENTS, format_func=dept_name, key="adm_dept")
        active = st.checkbox("Active", value=True, key="adm_active")
        submitted = st.form_submit_button("Create")

    if submitted:
        nu = nu.strip()
        if len(nu) < 3:
            st.error("Username must be at least 3 characters.")
        elif len(npw) < 8:
            st.error("Password must be at least 8 characters.")
        elif any(str(x.get("username", "")).lower() == nu.lower() for x in users):
            st.error("Username already exists.")
        else:
            rec = {
                "id": str(uuid.uuid4()),
                "username": nu,
                "password_hash": hash_password(npw),
                "role": role,
                "department": dept,
                "active": bool(active),
                "created_at": now_iso(),
            }
            users.append(rec)
            save_users(users)
            audit("admin_create_user", u, {"username": nu, "role": role, "department": dept, "active": bool(active)})
            st.success("User created.")
            st.rerun()

    st.divider()
    st.subheader("Users List")
    view = []
    for x in users:
        view.append(
            {
                "id": x.get("id"),
                "username": x.get("username"),
                "role": role_name(str(x.get("role"))),
                "department": dept_name(str(x.get("department"))),
                "active": x.get("active", True),
                "created_at": x.get("created_at"),
            }
        )
    st.dataframe(view, use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Edit User")
    options = {f"{x.get('username')} • {role_name(str(x.get('role')))} • {dept_name(str(x.get('department')))}": x.get("id") for x in users}
    pick = st.selectbox("Select user", list(options.keys()), key="adm_pick")
    uid = options[pick]
    target = next(x for x in users if x.get("id") == uid)

    t_active = st.checkbox("Active", value=bool(target.get("active", True)), key=f"t_active_{uid}")
    t_role = st.selectbox(
        "Role",
        ROLES,
        index=ROLES.index(str(target.get("role", "dept_rep"))),
        format_func=role_name,
        key=f"t_role_{uid}",
    )
    t_dept = st.selectbox(
        "Department",
        DEPARTMENTS,
        index=DEPARTMENTS.index(str(target.get("department", "IT"))) if str(target.get("department", "IT")) in DEPARTMENTS else 0,
        format_func=dept_name,
        key=f"t_dept_{uid}",
    )
    new_pw = st.text_input("Reset password (optional, >=8 chars)", type="password", key=f"t_pw_{uid}")

    if st.button("Apply Changes", key=f"t_apply_{uid}"):
        target["active"] = bool(t_active)
        target["role"] = t_role
        target["department"] = t_dept
        target["updated_at"] = now_iso()
        if new_pw.strip():
            if len(new_pw) < 8:
                st.error("Password must be at least 8 characters.")
                st.stop()
            target["password_hash"] = hash_password(new_pw)

        save_users(users)
        audit("admin_update_user", u, {"user_id": uid, "role": t_role, "department": t_dept, "active": bool(t_active)})
        st.success("User updated.")
        st.rerun()


# ============================================================
# Main
# ============================================================
def main() -> None:
    st.set_page_config(page_title=APP_TITLE, layout="wide")
    ensure_data_files()

    st.title(APP_TITLE)
    st.caption(APP_TAGLINE)

    menu = render_sidebar()

    if menu == "Initial Setup":
        page_initial_setup()
        return

    if menu == "Login":
        page_login()
        return

    if menu == "Dashboard":
        page_dashboard()
    elif menu == "Threat Intel":
        page_threat_intel()
    elif menu == "Incidents":
        page_incidents()
    elif menu == "PCAP Analyzer":
        page_pcap()
    elif menu == "Audit Log":
        page_audit_log()
    elif menu == "Admin":
        page_admin()


if __name__ == "__main__":
    if "user" not in st.session_state:
        st.session_state["user"] = None
    main()
