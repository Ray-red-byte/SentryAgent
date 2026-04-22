import axios from 'axios';

// ---------------------------------------------------------------------------
// Axios Instance
// ---------------------------------------------------------------------------
const api = axios.create({
    baseURL: 'http://localhost:8000/v2',
    headers: { 'Content-Type': 'application/json' },
});

// ---------------------------------------------------------------------------
// Token helpers  (localStorage so the session survives a page refresh)
// ---------------------------------------------------------------------------
export const tokenStore = {
    get: () => localStorage.getItem('sentry_token'),
    set: (tok) => localStorage.setItem('sentry_token', tok),
    clear: () => localStorage.removeItem('sentry_token'),
};

// ---------------------------------------------------------------------------
// Login helper — posts OAuth2 form data and returns the access_token
// ---------------------------------------------------------------------------
export async function login(username, password) {
    // The backend expects application/x-www-form-urlencoded (OAuth2 standard)
    const params = new URLSearchParams();
    params.append('username', username);
    params.append('password', password);

    const res = await axios.post('http://localhost:8000/v2/auth/token', params, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    const token = res.data.access_token;
    tokenStore.set(token);
    return token;
}

export function logout() {
    tokenStore.clear();
}

// ---------------------------------------------------------------------------
// Request interceptor — attach Bearer token to every outgoing request
// ---------------------------------------------------------------------------
api.interceptors.request.use((config) => {
    const token = tokenStore.get();
    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
});

// ---------------------------------------------------------------------------
// Response interceptor — on 401 clear token so the app re-shows login
// ---------------------------------------------------------------------------
api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            tokenStore.clear();
            // Dispatch a custom event so App.jsx can react without a hard reload
            window.dispatchEvent(new Event('sentry:logout'));
        }
        return Promise.reject(error);
    }
);

export default api;