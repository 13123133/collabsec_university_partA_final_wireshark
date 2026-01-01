# Cybersecurity Collaboration Portal (University) — Part A (Final)

A **university campus** system for:
- Cross-department collaboration (Department field everywhere)
- Threat intelligence sharing (IOC board)
- Incident response workflow (tickets + assignment + collaborators)
- Secure communication (incident comments)
- Evidence handling (file upload per incident)
- Packet analysis (PCAP upload + IP extraction + IOC match) using Scapy
- Audit log + in-app notifications
- **No public registration**: Admin creates accounts
- **No database**: JSON files stored in `app/data/`

## Run (Windows, easiest)
1. Extract the zip
2. Double-click `run.bat`
3. Browser will open automatically

## First-time setup
If there are no users, the app will show **Initial Setup**:
- Create the first **Admin (Security Team)** account.

After that:
- Go to **Admin** page to create other users (IT/Library/Admin/Health/Faculty).

## Data files
Stored under `app/data/`:
- `users.json`
- `iocs.json`
- `incidents.json`
- `audit.json`
- `notifications.json`
- Evidence uploads: `app/data/uploads/<incident_id>/...`
