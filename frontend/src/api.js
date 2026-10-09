// Appels au backend FastAPI (via le proxy Vite → :8080)
// Le jeton JWT est stocké en mémoire + localStorage et ajouté à chaque requête.

const TOKEN_KEY = 'socai_token';

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}
export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

// Wrapper fetch avec en-tête d'autorisation
async function apiFetch(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(path, { ...options, headers });

  if (res.status === 401) {
    clearToken();
    window.location.href = '/login';
    throw new Error('Session expirée');
  }
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail || `Erreur ${res.status}`);
  }
  return res.json();
}

// --- Auth ---
export async function login(username, password) {
  // Le backend attend un formulaire OAuth2 (username + password)
  const body = new URLSearchParams({ username, password });
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail || 'Identifiants incorrects');
  }
  return res.json(); // { access_token, user }
}

export function getMe() {
  return apiFetch('/api/auth/me');
}

// --- Incidents & KPIs ---
export function getKpis() {
  return apiFetch('/api/kpis');
}
export function getIncidents(params = {}) {
  const qs = new URLSearchParams(params).toString();
  return apiFetch(`/api/incidents${qs ? '?' + qs : ''}`);
}
export function getIncident(caseId) {
  return apiFetch(`/api/incidents/${caseId}`);
}
export function getIncidentAlerts(caseId) {
  return apiFetch(`/api/incidents/${caseId}/alerts`);
}

// --- Actions (Jour 2) ---
export function sendFeedback(caseId, label) {
  return apiFetch(`/api/incidents/${caseId}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ label }),
  });
}
export function approveBlock(caseId) {
  return apiFetch(`/api/incidents/${caseId}/approve`, {
    method: 'POST',
  });
}
