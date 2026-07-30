import requests

BASE  = 'http://127.0.0.1:8000'
ADMIN = {'X-API-Key': 'admin-secret-key-123'}
SVC   = {'X-API-Key': 'service-secret-key-789'}
AUD   = {'X-API-Key': 'auditor-secret-key-456'}

errors = []

def chk(label, r, expected=200):
    ok = r.status_code == expected
    tag = 'OK  ' if ok else 'FAIL'
    print(f'[{tag}] {label} -> {r.status_code}')
    if not ok:
        errors.append(f'{label}: status={r.status_code} body={r.text[:300]}')
    return r

# 1. Health
chk('GET  /health', requests.get(f'{BASE}/health'))

# 2. Auth
import uuid
unique_suffix = uuid.uuid4().hex[:8]
test_username = f'smokeuser_{unique_suffix}'
test_email = f'smoke_{unique_suffix}@test.com'

chk('POST /auth/register', requests.post(f'{BASE}/auth/register', json={
    'username': test_username, 'email': test_email,
    'password': 'pass123',   'role': 'admin'
}), 201)
r = chk('POST /auth/login', requests.post(f'{BASE}/auth/login', json={
    'username': test_username, 'password': 'pass123'
}))
jwt_token = r.json().get('access_token', '')
JWT = {'Authorization': f'Bearer {jwt_token}'}

# 3. Ingest log
r = chk('POST /logs/ingest', requests.post(f'{BASE}/logs/ingest', headers=SVC, json={
    'prompt': 'Call alice@example.com re SSN 000-12-3456',
    'response': 'Confirmed for alice@example.com',
    'agent_id': 'agent-smoke', 'user_id': 'usr_smoke',
    'retention_category': 'FINANCIAL'
}), 201)
log_id = r.json().get('id', '')

# 4. Get single log
chk('GET  /logs/{id}', requests.get(f'{BASE}/logs/{log_id}', headers=AUD))

# 5. Verify tamper detection
r = chk('GET  /verify/{id}', requests.get(f'{BASE}/verify/{log_id}', headers=AUD))
print(f'       tamper_valid={r.json().get("is_valid")}')

# 6. Reveal PII (admin only)
chk('GET  /logs/{id}/reveal', requests.get(f'{BASE}/logs/{log_id}/reveal', headers=ADMIN))

# 7. List logs with filter
r = chk('GET  /logs?agent_id=agent-smoke', requests.get(f'{BASE}/logs?agent_id=agent-smoke', headers=ADMIN))
print(f'       records_returned={len(r.json())}')

# 8. Ingest via LLM
r = chk('POST /logs/ingest-llm', requests.post(f'{BASE}/logs/ingest-llm', headers=ADMIN, json={
    'prompt': 'My email is john@example.com and phone 555-999-1234',
    'agent_id': 'ai-agent-01', 'user_id': 'usr_smoke2',
    'retention_category': 'GENERAL'
}))
print(f'       llm_provider={r.json().get("llm_provider")}')

# 9. Retention policies CRUD
chk('GET  /retention/policies', requests.get(f'{BASE}/retention/policies'))
chk('POST /retention/policies', requests.post(f'{BASE}/retention/policies', headers=ADMIN,
    json={'category': 'LEGAL', 'retention_days': 180}), 201)
chk('DEL  /retention/policies/LEGAL', requests.delete(f'{BASE}/retention/policies/LEGAL', headers=ADMIN))

# 10. Simulate time travel
r = chk('POST /retention/simulate-time', requests.post(f'{BASE}/retention/simulate-time', headers=ADMIN,
    json={'days_forward': 91}))
print(f'       swept={r.json().get("records_swept")}')

# 11. PII vault
r = chk('GET  /admin/pii/tokens', requests.get(f'{BASE}/admin/pii/tokens', headers=ADMIN))
print(f'       pii_tokens={len(r.json())}')

# 12. Access logs
r = chk('GET  /access-logs', requests.get(f'{BASE}/access-logs', headers=ADMIN))
print(f'       access_entries={len(r.json())}')

# 13. DSAR
chk('GET  /dsar/usr_smoke', requests.get(f'{BASE}/dsar/usr_smoke', headers=ADMIN))
chk('POST /dsar/usr_smoke/delete', requests.post(f'{BASE}/dsar/usr_smoke/delete', headers=ADMIN))

# 14. Prometheus metrics
chk('GET  /metrics', requests.get(f'{BASE}/metrics'))

# 15. JWT token on protected endpoint
chk('GET  /access-logs via JWT', requests.get(f'{BASE}/access-logs', headers=JWT))

print()
if errors:
    print(f'ERRORS ({len(errors)}):')
    for e in errors:
        print(f'  - {e}')
else:
    print('ALL ENDPOINTS PASSED')
