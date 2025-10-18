// ---------- Final script.js (PKCE + auto refresh + currently-playing + JSON → Spreadsheet) ----------

// --- CONFIG: ganti redirectUri sesuai host kamu ---
const clientId = '2c9f3936abbb4601a68f7203b959092b';
const redirectUri = 'https://loopforever25-byte.github.io/spotify-viewer/'; // ganti sesuai deploy
const sheetUrl = 'https://script.google.com/macros/s/AKfycbxGNc2FIsX3yLQIcEr1j1Shm8q1QDyCmU71cI6HreUhsMbDap1z1Wqzsji8AjIsJLV1/exec'; // ganti dengan Apps Script URL

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
function escapeHtml(s = '') {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
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
  if (!refresh_token) return null;
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

// wrapper fetch auto-refresh
async function apiFetch(url, opts = {}) {
  const token = localStorage.getItem('access_token');
  if (!token) throw new Error('no_access_token');
  opts.headers = Object.assign({}, opts.headers, { Authorization: `Bearer ${token}` });

  let res = await fetch(url, opts);
  if (res.status === 401) {
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
  updateJSONFile(lastData);
}

// -------------------- Kirim JSON ke Spreadsheet --------------------
async function updateJSONFile(data) {
  try {
    const jsonText = JSON.stringify(data, null, 2);
    document.getElementById('json-output').textContent = jsonText; // opsional tampilkan

    await fetch(sheetUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: jsonText
    });

  } catch (err) {
    console.error("Gagal kirim ke spreadsheet:", err);
  }
}

// -------------------- Auto refresh --------------------
function scheduleTokenAutoRefresh() {
  if (refreshTimerId) clearTimeout(refreshTimerId);
  const expiresAt = Number(localStorage.getItem('expires_at')) || 0;
  const now = Date.now();
  const msUntil = expiresAt > now ? Math.max(1000, expiresAt - now - 60*1000) : 55*60*1000;
  refreshTimerId = setTimeout(async () => {
    const newT = await refreshAccessToken();
    if (newT) scheduleTokenAutoRefresh();
  }, msUntil);
}

// -------------------- Logout --------------------
function logout() {
  ['access_token','refresh_token','expires_at','spotify_current','pkce_verifier'].forEach(k=>localStorage.removeItem(k));
  window.location.href = redirectUri;
}

// -------------------- Init / Main --------------------
(async function init(){
  authorizeBtn.addEventListener('click', redirectToAuthCodeFlow);
  logoutBtn.addEventListener('click', logout);

  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  if (code) {
    try {
      accessToken = await exchangeCodeForToken(code);
      window.history.replaceState({}, document.title, redirectUri);
    } catch (e) { console.error('exchange error', e); }
  }

  accessToken = localStorage.getItem('access_token') || accessToken || null;

  if (!accessToken) {
    authorizeBtn.style.display = 'inline-block';
    playerSection.style.display = 'none';
    return;
  }

  authorizeBtn.style.display = 'none';
  playerSection.style.display = 'block';
  scheduleTokenAutoRefresh();

  const d = await getCurrentlyPlaying();
  updateDisplay(d);

  setInterval(async () => {
    const res = await getCurrentlyPlaying();
    updateDisplay(res);
  }, 10000);
})();
