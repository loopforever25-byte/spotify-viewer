// ---------- Final script.js (PKCE + auto refresh + currently-playing + JSON live) ----------

// --- CONFIG: ganti redirectUri sesuai host kamu (harus sama di Spotify Dashboard) ---
const clientId = '2c9f3936abbb4601a68f7203b959092b';
const redirectUri = 'http://127.0.0.1:5500/'; // <-- ganti dengan https://username.github.io/repo/ saat deploy

// --- Elemen DOM ---
const authorizeBtn = document.getElementById('authorize-btn');
const logoutBtn = document.getElementById('logout-btn');
const playerSection = document.getElementById('player-section');
const nowPlayingDiv = document.getElementById('now-playing');
const jsonOutput = document.getElementById('json-output');

let accessToken = null;
let refreshTimerId = null;
let lastData = {};

// -------------------- Utilities --------------------
function generateRandomString(length) {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from(crypto.getRandomValues(new Uint8Array(length)))
    .map(x => possible[x % possible.length]).join('');
}
async function generateCodeChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

// -------------------- Token exchange & refresh --------------------
async function exchangeCodeForToken(code) {
  const verifier = localStorage.getItem('pkce_verifier');
  const params = new URLSearchParams({
    client_id: clientId,
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier
  });

  const resp = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  });
  const data = await resp.json();
  if (data.access_token) {
    localStorage.setItem('access_token', data.access_token);
    if (data.refresh_token) localStorage.setItem('refresh_token', data.refresh_token);
    // save expiry
    const expiresAt = Date.now() + (data.expires_in || 3600) * 1000;
    localStorage.setItem('expires_at', String(expiresAt));
    return data.access_token;
  } else {
    console.error('Token exchange failed', data);
    return null;
  }
}

async function refreshAccessToken() {
  const refresh_token = localStorage.getItem('refresh_token');
  if (!refresh_token) {
    console.warn('No refresh_token found.');
    return null;
  }
  const params = new URLSearchParams({
    client_id: clientId,
    grant_type: 'refresh_token',
    refresh_token
  });

  try {
    const resp = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params
    });
    const data = await resp.json();
    if (data.access_token) {
      localStorage.setItem('access_token', data.access_token);
      if (data.refresh_token) localStorage.setItem('refresh_token', data.refresh_token);
      const expiresAt = Date.now() + (data.expires_in || 3600) * 1000;
      localStorage.setItem('expires_at', String(expiresAt));
      console.log('Access token refreshed');
      return data.access_token;
    } else {
      console.error('Refresh failed', data);
      return null;
    }
  } catch (err) {
    console.error('Refresh error', err);
    return null;
  }
}

// wrapper fetch yang auto-refresh kalau 401
async function apiFetch(url, opts = {}) {
  const token = localStorage.getItem('access_token');
  if (!token) throw new Error('no_access_token');
  opts.headers = Object.assign({}, opts.headers, { Authorization: `Bearer ${token}` });

  let res = await fetch(url, opts);
  if (res.status === 401) {
    // try refresh then retry once
    const newToken = await refreshAccessToken();
    if (!newToken) throw new Error('refresh_failed');
    opts.headers.Authorization = `Bearer ${newToken}`;
    res = await fetch(url, opts);
  }
  return res;
}

// -------------------- PKCE login flow --------------------
async function redirectToAuthCodeFlow() {
  const verifier = generateRandomString(128);
  const challenge = await generateCodeChallenge(verifier);
  localStorage.setItem('pkce_verifier', verifier);

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: 'user-read-private user-read-email user-read-currently-playing user-read-playback-state',
    code_challenge_method: 'S256',
    code_challenge: challenge
  });

  window.location.href = `https://accounts.spotify.com/authorize?${params.toString()}`;
}

// -------------------- Currently playing / UI --------------------
async function getCurrentlyPlaying() {
  try {
    const res = await apiFetch('https://api.spotify.com/v1/me/player/currently-playing');
    if (res.status === 204) return null;
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    console.error('getCurrentlyPlaying error', err);
    return null;
  }
}

function updateDisplay(data) {
  if (!data || !data.item) {
    nowPlayingDiv.innerHTML = `<p>Tidak ada lagu yang sedang diputar 🎧</p>`;
    lastData = { is_playing: false };
  } else {
    const track = data.item;
    const artists = track.artists.map(a => a.name).join(', ');
    nowPlayingDiv.innerHTML = `
      <h2>${escapeHtml(track.name)}</h2>
      <p>${escapeHtml(artists)} — ${escapeHtml(track.album.name)}</p>
      <img src="${track.album.images?.[0]?.url || ''}" alt="${escapeHtml(track.name)}">
    `;
    lastData = {
      is_playing: data.is_playing,
      track_name: track.name,
      artist_name: artists,
      album_name: track.album.name,
      album_art: track.album.images?.[0]?.url || null,
      progress_ms: data.progress_ms || 0,
      duration_ms: track.duration_ms || 0
    };
  }
  localStorage.setItem('spotify_current', JSON.stringify(lastData));
  jsonOutput.textContent = JSON.stringify(lastData, null, 2);
}

// small helper to avoid XSS if scraped or displayed
function escapeHtml(s = '') {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// -------------------- Auto refresh management --------------------
function scheduleTokenAutoRefresh() {
  // clear existing timer
  if (refreshTimerId) clearTimeout(refreshTimerId);
  const expiresAt = Number(localStorage.getItem('expires_at')) || 0;
  const now = Date.now();
  // refresh 60 seconds before expiry or in 55 minutes if unknown
  const msUntil = expiresAt > now ? Math.max(1000, expiresAt - now - 60*1000) : 55*60*1000;
  refreshTimerId = setTimeout(async () => {
    const newT = await refreshAccessToken();
    if (newT) {
      scheduleTokenAutoRefresh();
    }
  }, msUntil);
}

// -------------------- Logout --------------------
function logout() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('expires_at');
  localStorage.removeItem('spotify_current');
  localStorage.removeItem('pkce_verifier');
  window.location.href = redirectUri; // reload clean
}

// -------------------- Init / Main --------------------
(async function init(){
  // wire buttons
  authorizeBtn.addEventListener('click', redirectToAuthCodeFlow);
  logoutBtn.addEventListener('click', logout);

  // If OAuth callback contains code, exchange it
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  if (code) {
    try {
      accessToken = await exchangeCodeForToken(code);
      // remove code from URL
      window.history.replaceState({}, document.title, redirectUri);
    } catch (e) {
      console.error('exchange error', e);
    }
  }

  // load stored token if any
  accessToken = localStorage.getItem('access_token') || accessToken || null;

  if (!accessToken) {
    // show auth button
    authorizeBtn.style.display = 'inline-block';
    playerSection.style.display = 'none';
    return;
  }

  // token exists: schedule refresh & show UI
  authorizeBtn.style.display = 'none';
  playerSection.style.display = 'block';

  scheduleTokenAutoRefresh();

  // initial display
  const d = await getCurrentlyPlaying();
  updateDisplay(d);

  // periodically update currently playing and store JSON (10s)
  setInterval(async () => {
    const res = await getCurrentlyPlaying();
    updateDisplay(res);
  }, 100);
})();
