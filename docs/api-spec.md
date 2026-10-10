# VaultSync Sync API Specification

Version: `0.1.0` (Draft)  
Base URL: `/api/v1`

---

## 1. Endpoints Overview

| Method | Endpoint | Description | Phase |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Server operational health & version | Phase 1 (Active) |
| `GET` | `/api/v1/health` | Versioned operational health | Phase 1 (Active) |
| `POST` | `/api/v1/auth/register` | User account registration (salt registration) | Phase 3 |
| `POST` | `/api/v1/auth/login` | Session token issuance via challenge | Phase 3 |
| `POST` | `/api/v1/devices` | Enroll new device and session | Phase 3 |
| `DELETE`| `/api/v1/devices/{device_id}` | Revoke device session | Phase 3 |
| `GET` | `/api/v1/sync` | Pull encrypted changes since cursor | Phase 3 |
| `POST` | `/api/v1/sync` | Push encrypted changes / conflict detection | Phase 3 |

---

## 2. Active Endpoints (Phase 1)

### `GET /health` and `GET /api/v1/health`

Returns operational status, release version, runtime environment, and current UTC timestamp.

#### Response Headers
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Cache-Control: no-store, max-age=0`

#### Status 200 OK
```json
{
  "status": "ok",
  "version": "0.1.0",
  "environment": "development",
  "timestamp": "2026-10-10T18:41:00.123456+00:00"
}
```
