// ── CONFIG ──────────────────────────────────────────────────────────────────
const API            = window.__GBS_API_BASE__ || "/gbs";
const ROPROXY_USERS  = "https://users.roproxy.com";
const ROPROXY_THUMB  = "https://thumbnails.roproxy.com";
const PAGE_SIZE      = 25;

// ── STATE ────────────────────────────────────────────────────────────────────
let currentUser   = null;
let fullBanList   = [];
let filteredList  = [];
let currentPage   = 1;

const robloxCache = {};

// ── ROBLOX LOOKUPS VIA ROPROXY ───────────────────────────────────────────────
async function fetchRobloxInfo(userIds) {
  const missing = userIds.filter(id => id && !robloxCache[id]);
  if (!missing.length) return;
  for (const id of missing) robloxCache[id] = { username: null, avatarUrl: null, isBanned: null };
  await Promise.allSettled(missing.map(async id => {
    try {
      const res = await fetch(`${ROPROXY_USERS}/v1/users/${id}`);
      if (res.ok) {
        const u = await res.json();
        if (u && u.name) robloxCache[id].username = u.name;
        if (u) robloxCache[id].isBanned = u.isBanned === true;
      }
    } catch {}
  }));
  try {
    const qs = missing.map(id => `userIds=${encodeURIComponent(id)}`).join('&');
    const res = await fetch(`${ROPROXY_THUMB}/v1/users/avatar-headshot?${qs}&size=48x48&format=Png&isCircular=false`);
    if (res.ok) {
      const data = await res.json();
      for (const t of (data.data || [])) {
        const id = String(t.targetId);
        if (robloxCache[id] && t.imageUrl) robloxCache[id].avatarUrl = t.imageUrl;
      }
    }
  } catch {}
}

// ── INIT ─────────────────────────────────────────────────────────────────────
async function init() {
  var _sc = document.querySelector('.stat-card[data-filter=""]'); if (_sc) _sc.classList.add('active');
  await loadStats();
  await loadBans();
  await fetchMe();
}

// ── AUTH ─────────────────────────────────────────────────────────────────────
let isLoginMode = true;
function openModal(mode) {
  isLoginMode = mode === 'login';
  document.getElementById('authModal').classList.add('open');
  document.getElementById('modalTitle').textContent      = isLoginMode ? 'Login' : 'Register';
  document.getElementById('modalSub').textContent        = isLoginMode ? 'Access the moderation admin panel.' : 'New accounts require admin approval before access.';
  document.getElementById('modalSubmitBtn').textContent  = isLoginMode ? 'Login' : 'Register';
  document.getElementById('modalSubmitBtn').style.display = '';
  document.getElementById('usernameField').style.display = isLoginMode ? 'none' : 'block';
  document.getElementById('toggleLabel').textContent     = isLoginMode ? 'Need an account? Register' : 'Have an account? Login';
  document.querySelector('#authModal .modal-footer .link-btn').onclick = toggleAuthMode;
}
function toggleAuthMode() { openModal(isLoginMode ? 'register' : 'login'); }
document.getElementById('authModal').addEventListener('click', e => {});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') document.getElementById('resetModal').classList.remove('open');
});

async function submitAuth() {
  const email    = document.getElementById('inputEmail').value.trim();
  const password = document.getElementById('inputPassword').value;
  if (!email || !password) return toast('Fill in all fields', 'error');
  const btn = document.getElementById('modalSubmitBtn');
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.innerHTML = `<span class="btn-spinner"></span>${isLoginMode ? 'Logging in...' : 'Registering...'}`;

  if (isLoginMode) {
    const fd = new URLSearchParams();
    fd.append('username', email); fd.append('password', password);
    const r = await apiFetch('/auth/login', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: fd.toString() }, false);
    btn.disabled = false;
    btn.textContent = originalText;
    if (!r) return;
    document.getElementById('authModal').classList.remove('open');
    await fetchMe();
    toast('Logged in', 'success');
  } else {
    const username = document.getElementById('inputUsername').value.trim();
    if (!username) { btn.disabled = false; btn.textContent = originalText; return toast('Enter a username', 'error'); }
    const r = await apiFetch('/auth/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email, password, username }) }, false);
    btn.disabled = false;
    btn.textContent = originalText;
    if (!r) return;
    if (r.status === 'approved') {
      const fd = new URLSearchParams();
      fd.append('username', email); fd.append('password', password);
      const loggedIn = await apiFetch('/auth/login', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: fd.toString() }, false);
      if (loggedIn) {
        document.getElementById('authModal').classList.remove('open');
        await fetchMe();
        toast('Account created and logged in', 'success');
      }
      return;
    }
    document.getElementById('modalTitle').textContent = 'Account Created';
    document.getElementById('modalSub').textContent   = r.message;
    document.getElementById('modalSubmitBtn').style.display = 'none';
    document.getElementById('toggleLabel').textContent = 'Back to Login';
    document.querySelector('#authModal .modal-footer .link-btn').onclick = () => openModal('login');
  }
}

async function fetchMe() {
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const res = await fetch(API + '/auth/me', { credentials: 'same-origin' });
      if (res.status === 401 || res.status === 403) { currentUser = null; return; }
      if (!res.ok) { await new Promise(r => setTimeout(r, 3000)); continue; }
      const user = await res.json();
      currentUser = user;
      const redactedEmail = user.email.replace(/(.{2})[^@]+(@.+)/, '$1***$2');
      document.getElementById('loginPrompt').style.display      = 'none';
      document.getElementById('adminLogoutBtn').style.display   = 'flex';
      document.getElementById('loggedEmail').textContent        = redactedEmail;
      document.getElementById('adminLoggedAs').textContent      = `logged in as: ${redactedEmail}`;
      document.getElementById('actionHead').style.display       = '';
      document.getElementById('checkHead').style.cssText        = 'width:36px;padding:10px 12px;';
      document.getElementById('groupActionHead').style.display  = '';
      document.getElementById('groupCheckHead').style.cssText   = 'width:36px;padding:10px 12px;';
      if (user.is_admin) {
        document.getElementById('tabUsers').style.display   = '';
        document.getElementById('tabLogsBtn').style.display = '';
      }
      _rulesAgreed = false;
      showStaffPanels();
      renderPage();
      if (document.getElementById('tabGroupsPanel').style.display !== 'none') loadGroups();
      return;
    } catch {
      if (attempt < 4) await new Promise(r => setTimeout(r, 3000));
    }
  }
  toast('API unreachable — will retry on next action', 'error');
}

async function logout() {
  try {
    await fetch(API + '/auth/logout', { method: 'POST', credentials: 'same-origin' });
  } catch {}
  currentUser = null;
  document.getElementById('adminPanel').style.setProperty('display', 'none', 'important');
  document.getElementById('groupAdminPanel').style.setProperty('display', 'none', 'important');
  document.getElementById('rulesPanel').style.setProperty('display', 'none', 'important');
  document.getElementById('loginPrompt').style.display    = '';
  document.getElementById('adminLogoutBtn').style.display = 'none';
  document.getElementById('actionHead').style.display       = 'none';
  document.getElementById('checkHead').style.cssText        = 'width:0;padding:0;overflow:hidden;';
  document.getElementById('bulkBar').style.display          = 'none';
  document.getElementById('groupActionHead').style.display  = 'none';
  document.getElementById('groupCheckHead').style.cssText   = 'width:0;padding:0;overflow:hidden;';
  document.getElementById('groupBulkBar').style.display     = 'none';
  document.getElementById('tabUsers').style.display         = 'none';
  document.getElementById('tabLogsBtn').style.display       = 'none';
  switchTab('bans', document.querySelector('.tab'));
  renderPage();
}

// ── STATS ────────────────────────────────────────────────────────────────────
async function loadStats() {
  const r = await apiFetch('/bans/stats', {}, false);
  if (!r) return;
  document.getElementById('statTotal').textContent      = r.total;
  document.getElementById('statExploiters').textContent = r.exploiters;
  document.getElementById('statStolen').textContent     = r.stolen  || 0;
  document.getElementById('statBypass').textContent     = r.bypass  || 0;
  document.getElementById('statBots').textContent       = r.bots    || 0;
}

// ── BANS ─────────────────────────────────────────────────────────────────────
async function loadBans() {
  const r = await apiFetch('/bans', {}, false);
  if (!r) return;
  fullBanList = [...r.bans].reverse().map(b => ({
    userId:     b.userId,
    date:       b.date     || null,
    bannedBy:   b.bannedBy || null,
    message:    cleanMessage(b.message),
    rawMessage: b.message,
  }));
  document.getElementById('statTotal').textContent = r.total;
  applyFilter();
}

function cleanMessage(msg) {
  const idIdx = msg.indexOf(' | ID;');
  if (idIdx !== -1) msg = msg.slice(0, idIdx);
  msg = msg.replace(/^\[.*?\]\s*/, '').trim();
  return msg;
}

function escHtml(s) {
  return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatDate(iso) {
  if (!iso || iso === '2026-03-21') return '<span style="color:var(--muted2)">—</span>';
  const [y, m, d] = iso.split('-');
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return `${parseInt(d)} ${months[parseInt(m)-1]}. ${y}`;
}

function getTag(msg) {
  const l = (msg || '').toLowerCase();
  if (l.includes('exploit'))                                                    return 'exploiter';
  if (l.includes('safety'))                                                     return 'safety';
  if (l.includes('bypass'))                                                     return 'bypass';
  if (l.includes('bot') || l.includes('spam'))                                  return 'bot';
  if (l.includes('allegation'))                                                 return 'allegations';
  if (l.includes('stolen') || l.includes('stealer') || l.includes('assets'))   return 'stolen';
  if (l.includes('abuse'))                                                      return 'abuse';
  return 'general';
}
const TAG_LABELS = {
  exploiter:'Exploit', safety:'Safety Issue', bypass:'Bypass',
  bot:'Bot', allegations:'Allegations', stolen:'Stolen Assets', abuse:'Abuse', general:'Other'
};

function applyFilter() {
  const q   = document.getElementById('searchInput').value.toLowerCase().trim();
  const cat = document.getElementById('categoryFilter').value;
  filteredList = fullBanList.filter(b => {
    const cached = robloxCache[b.userId];
    const matchQ = !q
      || b.userId.toLowerCase().includes(q)
      || b.message.toLowerCase().includes(q)
      || ((cached && cached.username) ? cached.username : '').toLowerCase().includes(q);
    const matchC = !cat || getTag(b.rawMessage || b.message) === cat;
    return matchQ && matchC;
  });
  currentPage = 1;
  document.getElementById('showingCount').textContent = filteredList.length;
  renderPage();
}

// ── RENDER PAGE ───────────────────────────────────────────────────────────────
async function renderPage() {
  const tbody      = document.getElementById('banBody');
  const total      = filteredList.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (currentPage > totalPages) currentPage = totalPages;
  const slice = filteredList.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  if (!slice.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty">No results found.</td></tr>`;
    renderPagination(totalPages);
    return;
  }

  tbody.innerHTML = slice.map(b => buildRow(b)).join('');

  const uncached = slice.map(b => b.userId).filter(id => !robloxCache[id]);
  if (uncached.length) {
    await fetchRobloxInfo(uncached);
    for (const b of slice) {
      const info = robloxCache[b.userId];
      if (!info) continue;
      const avEl = document.getElementById(`av-${b.userId}`);
      const nmEl = document.getElementById(`nm-${b.userId}`);
      const unEl = document.getElementById(`un-${b.userId}`);
      const rbEl = document.getElementById(`rb-${b.userId}`);
      if (avEl) {
        if (info.avatarUrl) { avEl.classList.remove('loading'); avEl.innerHTML = `<img src="${escHtml(info.avatarUrl)}" alt=""/>`;  }
        else { avEl.classList.remove('loading'); avEl.textContent = '?'; }
        avEl.removeAttribute('id');
      }
      if (nmEl) {
        if (info.username) { nmEl.textContent = info.username; nmEl.classList.remove('unknown'); }
        nmEl.removeAttribute('id');
      }
      if (unEl) {
        if (info.username) { unEl.textContent = `@${info.username}`; unEl.style.opacity = ''; }
        unEl.removeAttribute('id');
      }
      if (rbEl) {
        if (info.isBanned === true)       { rbEl.textContent = 'Banned or Deactivated'; rbEl.className = 'rblx-badge rbanned'; }
        else if (info.isBanned === false) { rbEl.textContent = 'Active'; rbEl.className = 'rblx-badge ractive'; }
        else                              { rbEl.textContent = 'Unknown'; rbEl.className = 'rblx-badge runknown'; }
        rbEl.removeAttribute('id');
      }
    }
  }

  renderPagination(totalPages);
}

function buildRow(b) {
  const { userId, message, rawMessage, date, bannedBy } = b;
  const tag  = getTag(rawMessage || message);
  const info = robloxCache[userId];

  const avId = `av-${escHtml(userId)}`;
  let avHtml;
  if (info && info.avatarUrl) avHtml = `<div class="player-avatar"><img src="${escHtml(info.avatarUrl)}" alt=""/></div>`;
  else avHtml = `<div class="player-avatar loading" id="${avId}">…</div>`;

  const nmId = `nm-${userId}`;
  const unId = `un-${userId}`;
  let displayHtml, usernameHtml;
  if (info && info.username) {
    displayHtml  = `<span class="player-display">${escHtml(info.username)}</span>`;
    usernameHtml = `<span class="player-username">@${escHtml(info.username)}</span>`;
  } else {
    displayHtml  = `<span class="player-display unknown" id="${nmId}">Unknown</span>`;
    usernameHtml = `<span class="player-username" id="${unId}" style="opacity:0">@—</span>`;
  }

  const rbId = `rb-${userId}`;
  let rblxBadge;
  if (info === undefined || info === null) rblxBadge = `<span class="rblx-badge runknown" id="${rbId}">…</span>`;
  else if (info.isBanned === true)         rblxBadge = `<span class="rblx-badge rbanned">Banned or Deactivated</span>`;
  else if (info.isBanned === false)        rblxBadge = `<span class="rblx-badge ractive">Active</span>`;
  else                                     rblxBadge = `<span class="rblx-badge runknown" id="${rbId}">Unknown</span>`;

  const dateStr     = date ? formatDate(date) : '<span style="color:var(--muted2)">—</span>';
  const bannedByStr = bannedBy
    ? `<span style="font-family:var(--font-mono);font-size:11px;color:var(--muted)">${escHtml(bannedBy)}</span>`
    : '<span style="color:var(--muted2)">—</span>';

  const unbanTd = currentUser
    ? `<td><div class="action-btns"><button class="edit-btn" onclick="openEditModal('${escHtml(userId)}', '${escHtml(message).replace(/'/g,"\\'")}')">Edit</button><button class="unban-btn" onclick="removeBan('${escHtml(userId)}')">Unban</button></div></td>`
    : '<td></td>';

  const checkTd = currentUser
    ? `<td style="padding:10px 12px;width:36px;"><input type="checkbox" class="row-check" data-id="${escHtml(userId)}" onchange="onRowCheck()" style="cursor:pointer;accent-color:var(--red);"></td>`
    : '<td style="width:0;padding:0;overflow:hidden;"></td>';

  return `<tr>
    ${checkTd}
    <td>
      <div class="player-cell">
        <span class="expand-arrow">▶</span>
        ${avHtml}
        <div class="player-info">
          ${displayHtml}
          ${usernameHtml}
        </div>
      </div>
    </td>
    <td><a href="https://www.roblox.com/users/${escHtml(userId)}/profile" target="_blank">${escHtml(userId)}</a></td>
    <td><span class="tag ${tag}">${TAG_LABELS[tag]}</span></td>
    <td style="font-size:12px;word-break:break-word;white-space:normal" title="${escHtml(message)}">${escHtml(message) || '—'}</td>
    <td>${bannedByStr}</td>
    <td class="date-cell">${dateStr}</td>
    <td>${rblxBadge}</td>
    ${unbanTd}
  </tr>`;
}

// ── PAGINATION ────────────────────────────────────────────────────────────────
function renderPagination(totalPages) {
  const el = document.getElementById('pagination');
  if (totalPages <= 1) { el.innerHTML = ''; return; }
  let html = `<button class="page-btn" onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>‹ Prev</button>`;
  const nums = getPageNums(currentPage, totalPages);
  let prev = null;
  for (const p of nums) {
    if (prev !== null && p - prev > 1) html += `<span class="page-ellipsis">…</span>`;
    html += `<button class="page-btn ${p===currentPage?'active':''}" onclick="goPage(${p})">${p}</button>`;
    prev = p;
  }
  html += `<button class="page-btn" onclick="goPage(${currentPage+1})" ${currentPage===totalPages?'disabled':''}>Next ›</button>`;
  el.innerHTML = html;
}

function getPageNums(cur, total) {
  const s = new Set([1, total, cur, cur-1, cur+1].filter(p => p >= 1 && p <= total));
  return [...s].sort((a,b) => a-b);
}

function goPage(p) {
  const total = Math.ceil(filteredList.length / PAGE_SIZE);
  if (p < 1 || p > total) return;
  currentPage = p;
  window.scrollTo({ top: document.getElementById('tabBans').offsetTop - 60, behavior: 'smooth' });
  renderPage();
}

// ── USERNAME LOOKUP ───────────────────────────────────────────────────────────
let _lookupUserId = null;

async function lookupUser() {
  const username = document.getElementById('inLookupUsername').value.trim();
  if (!username) return;
  const resultEl = document.getElementById('lookupResult');
  const errorEl  = document.getElementById('lookupError');
  const btn      = document.querySelector('button[onclick="lookupUser()"]');
  resultEl.style.display = 'none';
  errorEl.textContent = '';
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="btn-spinner"></span>'; }
  try {
    const res = await fetch(`${API}/users/lookup?username=${encodeURIComponent(username)}`);
    if (!res.ok) { errorEl.textContent = `No user found for "${username}"`; return; }
    const user = await res.json();
    _lookupUserId = String(user.id);
    document.getElementById('lookupAvatar').src = escHtml(user.avatarUrl || '');
    document.getElementById('lookupName').textContent = user.displayName || user.username;
    document.getElementById('lookupId').textContent = `ID: ${user.id} · @${user.username}`;
    resultEl.style.display = 'flex';
  } catch(e) {
    errorEl.textContent = 'Lookup failed — try again';
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '⌕ Search'; }
  }
}

function useLookupId() {
  if (!_lookupUserId) return;
  const field = document.getElementById('inUserId');
  const existing = field.value.trim();
  if (existing) {
    const ids = existing.split(',').map(s => s.trim()).filter(Boolean);
    if (!ids.includes(_lookupUserId)) field.value = [...ids, _lookupUserId].join(', ');
  } else {
    field.value = _lookupUserId;
  }
  document.getElementById('inLookupUsername').value = '';
  document.getElementById('lookupResult').style.display = 'none';
  _lookupUserId = null;
  toast(`Added ID ${field.value.split(',').pop().trim()} to ban list`, 'success');
}

// ── OPTIMISTIC LOCAL UPDATES ──────────────────────────────────────────────────
function localRemoveBans(userIds) {
  const idSet = new Set(userIds);
  fullBanList = fullBanList.filter(b => !idSet.has(b.userId));
  applyFilter();
  loadStats();
}

function localAddBans(entries) {
  for (const e of entries) {
    if (!fullBanList.find(b => b.userId === e.userId)) fullBanList.unshift(e);
  }
  applyFilter();
  loadStats();
}

function localEditBans(userIds, message) {
  const idSet = new Set(userIds);
  for (const b of fullBanList) {
    if (idSet.has(b.userId)) { b.rawMessage = message; b.message = cleanMessage(message); }
  }
  applyFilter();
}

async function addBan() {
  const rawIds   = document.getElementById('inUserId').value.trim();
  const reason   = document.getElementById('inReason').value.trim();
  const category = document.getElementById('inCategory').value;
  if (!rawIds || !reason) return toast('Fill in User ID and Reason', 'error');
  const userIds = rawIds.split(',').map(id => id.trim()).filter(Boolean);
  if (!userIds.length) return toast('Enter at least one User ID', 'error');
  const message = `[${category}] ${reason}`;
  const btn = document.getElementById('addBanBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="btn-spinner"></span>Banning...';
  const r = await apiFetch('/bans/bulk', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userIds, message })
  });
  btn.disabled = false;
  btn.innerHTML = '+ Add Ban';
  if (!r) return;
  const added = r.added || [], skipped = r.skipped || [];
  if (added.length) toast(`Banned ${added.length} user${added.length > 1 ? 's' : ''}${skipped.length ? `, ${skipped.length} skipped` : ''}`, 'success');
  else if (skipped.length) toast(`No valid users banned — ${skipped.length} skipped (already banned or invalid ID)`, 'error');
  document.getElementById('inUserId').value = '';
  document.getElementById('inReason').value = '';
  const today = new Date().toISOString().split('T')[0];
  localAddBans(added.map(uid => ({
    userId: uid, message: cleanMessage(message), rawMessage: message,
    date: today, bannedBy: currentUser?.username || 'unknown'
  })));
}

// ── BULK UNBAN ────────────────────────────────────────────────────────────────
function getSelectedIds() {
  return [...document.querySelectorAll('.row-check:checked')].map(cb => cb.dataset.id);
}

function onRowCheck() {
  const ids = getSelectedIds();
  const bulkBar = document.getElementById('bulkBar');
  bulkBar.style.display = ids.length ? 'flex' : 'none';
  document.getElementById('bulkCount').textContent = `${ids.length} user${ids.length !== 1 ? 's' : ''} selected`;
}

function clearSelection() {
  document.querySelectorAll('.row-check').forEach(el => el.checked = false);
  document.getElementById('bulkBar').style.display = 'none';
}

function openBulkEditModal() {
  const ids = getSelectedIds();
  if (!ids.length) return;
  document.getElementById('bulkEditModalSub').textContent = `Updating reason for ${ids.length} user${ids.length !== 1 ? 's' : ''}.`;
  document.getElementById('bulkEditReasonInput').value = '';
  document.getElementById('bulkEditModal').classList.add('open');
  setTimeout(() => document.getElementById('bulkEditReasonInput').focus(), 50);
}

async function submitBulkEditReason() {
  const ids      = getSelectedIds();
  const reason   = document.getElementById('bulkEditReasonInput').value.trim();
  const category = document.getElementById('bulkEditCategory').value;
  if (!reason) return toast('Reason cannot be empty', 'error');
  const message = `[${category}] ${reason}`;
  const btn = document.getElementById('bulkEditBtn');
  btn.disabled = true; btn.innerHTML = '<span class="btn-spinner"></span>Saving...';
  const r = await apiFetch('/bans/bulk-edit', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userIds: ids, message })
  });
  btn.disabled = false; btn.innerHTML = 'Save Changes';
  if (!r) return;
  toast(`Updated reason for ${r.updated || ids.length} user${ids.length !== 1 ? 's' : ''}`, 'success');
  document.getElementById('bulkEditModal').classList.remove('open');
  clearSelection();
  localEditBans(ids, message);
}

async function bulkUnban() {
  const ids = getSelectedIds();
  if (!ids.length) return;
  if (!confirm(`Unban ${ids.length} user${ids.length !== 1 ? 's' : ''}?`)) return;
  const btn = document.querySelector('#bulkBar .btn-red');
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="btn-spinner"></span>Unbanning...'; }
  const r = await apiFetch('/bans/bulk-remove', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userIds: ids })
  });
  if (btn) { btn.disabled = false; btn.innerHTML = 'Unban Selected'; }
  if (!r) return;
  toast(`Unbanned ${r.removed || ids.length} user${ids.length !== 1 ? 's' : ''}`, 'success');
  clearSelection();
  localRemoveBans(ids);
}

async function removeBan(userId) {
  if (!confirm(`Unban ${userId}?`)) return;
  const btn = document.querySelector(`.unban-btn[onclick="removeBan('${userId}')"]`);
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="btn-spinner"></span>'; }
  const r = await apiFetch(`/bans/${userId}`, { method: 'DELETE' });
  if (btn) { btn.disabled = false; btn.innerHTML = 'Unban'; }
  if (!r) return;
  toast(`User ${userId} unbanned`, 'success');
  localRemoveBans([userId]);
}

// ── EDIT BAN REASON ───────────────────────────────────────────────────────────
let editTargetUserId = null;

function openEditModal(userId, currentMessage) {
  editTargetUserId = userId;
  const catMatch = currentMessage.match(/^\[(.+?)\]/);
  const cat = catMatch ? catMatch[1] : 'General';
  const reason = currentMessage.replace(/^\[.+?\]\s*/, '').trim();
  const sel = document.getElementById('editCategory');
  for (const opt of sel.options) { if (opt.value === cat) { opt.selected = true; break; } }
  document.getElementById('editReasonInput').value = reason;
  document.getElementById('editModalSub').textContent = `Editing ban for User ID: ${userId}`;
  document.getElementById('editModal').classList.add('open');
  setTimeout(() => document.getElementById('editReasonInput').focus(), 50);
}

let _editInFlight = false;

async function submitEditReason() {
  if (_editInFlight) return;
  const reason   = document.getElementById('editReasonInput').value.trim();
  const category = document.getElementById('editCategory').value;
  if (!reason) return toast('Reason cannot be empty', 'error');
  const message = `[${category}] ${reason}`;
  const btn = document.getElementById('editSubmitBtn');
  _editInFlight = true;
  btn.disabled = true;
  btn.innerHTML = '<span class="btn-spinner"></span>Saving...';
  const r = await apiFetch(`/bans/${editTargetUserId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message })
  });
  _editInFlight = false;
  btn.disabled = false;
  btn.innerHTML = 'Save Changes';
  if (!r) return;
  toast('Ban reason updated', 'success');
  document.getElementById('editModal').classList.remove('open');
  localEditBans([editTargetUserId], message);
  editTargetUserId = null;
}

// ── ADMIN USERS ───────────────────────────────────────────────────────────────
async function loadUsers() {
  const r = await apiFetch('/admin/users');
  if (!r) return;
  const tbody = document.getElementById('userBody');
  if (!r.length) { tbody.innerHTML = `<tr><td colspan="5" class="empty">No users.</td></tr>`; return; }
  tbody.innerHTML = r.map(u => {
    const safeEmail    = escHtml(u.email);
    const safeUsername = escHtml(u.username);
    const safeStatus   = escHtml(u.status);
    const safeDate     = u.created_at ? escHtml(u.created_at.split('T')[0]) : '—';
    const emailAttr    = safeEmail.replace(/'/g, "\\'");
    // Redact email by default
    const redacted     = safeEmail.replace(/(.{2})[^@]+(@.+)/, '$1***$2');
    const emailCell    = `<span data-full="${emailAttr}" data-redacted="${redacted}" data-shown="false"
      style="font-family:var(--font-mono);font-size:11px;cursor:pointer;color:var(--muted)" 
      title="Click to reveal"
      onclick="const s=this;const shown=s.dataset.shown==='true';s.textContent=shown?s.dataset.redacted:s.dataset.full;s.style.color=shown?'var(--muted)':'var(--text)';s.title=shown?'Click to reveal':'Click to hide';s.dataset.shown=shown?'false':'true';">${redacted}</span>`;
    return `<tr>
    <td>${emailCell}</td>
    <td>${safeUsername}</td>
    <td><span class="status-badge ${safeStatus}">${safeStatus}</span></td>
    <td>
      ${u.is_admin
        ? `<span class="rblx-badge rbanned" style="background:rgba(139,92,246,.12);color:#a078f0;border-color:rgba(139,92,246,.4);">Admin</span>`
        : `<span class="rblx-badge runknown">User</span>`}
    </td>
    <td class="date-cell">${safeDate}</td>
    <td style="display:flex;gap:6px;flex-wrap:nowrap;align-items:center">
      ${u.status==='pending'
        ? `<button class="btn btn-green btn-sm" onclick="approveUser('${emailAttr}')">Approve</button>
           <button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="rejectUser('${emailAttr}')">Reject</button>`
        : `<button class="btn btn-ghost btn-sm" style="opacity:.3;cursor:default" disabled>Approve</button>
           <button class="btn btn-ghost btn-sm" style="opacity:.3;cursor:default" disabled>Reject</button>`}
      ${!u.is_admin
        ? `<button class="btn btn-ghost btn-sm" onclick="promoteUser('${emailAttr}')">Make Admin</button>`
        : u.email === currentUser?.email
          ? `<button class="btn btn-ghost btn-sm" style="opacity:.3;cursor:default" disabled title="Cannot demote yourself">Admin ✓</button>`
          : u.is_owner
            ? `<button class="btn btn-ghost btn-sm" style="opacity:.3;cursor:default" disabled title="Owner account is protected">Owner ✓</button>`
            : `<button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="demoteUser('${emailAttr}')">Demote</button>`}
      ${u.is_owner && currentUser?.email !== u.email
        ? `<button class="btn btn-ghost btn-sm" style="opacity:.3;cursor:default" disabled title="Owner account is protected">Reset PW</button>
           <button class="btn btn-ghost btn-sm" style="opacity:.3;cursor:default" disabled title="Owner account is protected">Remove</button>`
        : `<button class="btn btn-ghost btn-sm" style="color:var(--yellow)" onclick="openResetModal('${emailAttr}')">Reset PW</button>
           <button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="removeUser('${emailAttr}')">Remove</button>`}
    </td>
  </tr>`;
  }).join('');
}

const LOG_PAGE_SIZE = 25;
let allLogs = [], logPage = 1;

const ACTION_META = {
  'ban.add':                { label: 'Ban Add',        cls: 'ban-add' },
  'ban.remove':             { label: 'Ban Remove',     cls: 'ban-remove' },
  'ban.edit':               { label: 'Ban Edit',       cls: 'ban-edit' },
  'group.ban.add':          { label: 'Group Ban Add',  cls: 'ban-add' },
  'group.ban.remove':       { label: 'Group Unban',    cls: 'ban-remove' },
  'group.ban.edit':         { label: 'Group Ban Edit', cls: 'ban-edit' },
  'user.approved':          { label: 'Approved',       cls: 'user-action' },
  'user.rejected':          { label: 'Rejected',       cls: 'user-action' },
  'user.promoted_to_admin': { label: 'Made Admin',     cls: 'danger' },
  'user.demoted_from_admin':{ label: 'Demoted Admin',  cls: 'danger' },
  'user.deleted':           { label: 'User Deleted',   cls: 'danger' },
  'user.password_reset':    { label: 'Password Reset', cls: 'user-action' },
  'auth.login':             { label: 'Login',          cls: 'auth' },
  'auth.logout':            { label: 'Logout',         cls: 'auth' },
  'auth.register':          { label: 'Register',       cls: 'auth' },
};

async function loadLogs() {
  const r = await apiFetch('/admin/logs');
  if (!r) return;
  allLogs = [...r].reverse();
  logPage = 1;
  renderLogs();
}

function redactEmail(val) {
  if (!val || val === '—') return escHtml(val || '—');
  // Only redact if it looks like an email
  if (!val.includes('@')) return escHtml(val);
  const safe     = escHtml(val);
  const redacted = escHtml(val.replace(/(.{2})[^@]+(@.+)/, '$1***$2'));
  const attr     = safe.replace(/'/g, "\\'");
  return `<span data-full="${attr}" data-redacted="${redacted}" data-shown="false"
    style="cursor:pointer;color:var(--muted)" title="Click to reveal"
    onclick="const s=this;const shown=s.dataset.shown==='true';s.textContent=shown?s.dataset.redacted:s.dataset.full;s.style.color=shown?'var(--muted)':'var(--text)';s.title=shown?'Click to reveal':'Click to hide';s.dataset.shown=shown?'false':'true';">${redacted}</span>`;
}

function renderLogs() {
  const tbody      = document.getElementById('logBody');
  const totalPages = Math.max(1, Math.ceil(allLogs.length / LOG_PAGE_SIZE));
  if (logPage > totalPages) logPage = totalPages;
  const slice = allLogs.slice((logPage - 1) * LOG_PAGE_SIZE, logPage * LOG_PAGE_SIZE);
  if (!slice.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty">No log entries yet.</td></tr>`;
    document.getElementById('logPagination').innerHTML = '';
    return;
  }
  tbody.innerHTML = slice.map(e => {
    const meta = ACTION_META[e.action] || { label: e.action, cls: 'auth' };
    const ts   = e.timestamp ? new Date(e.timestamp).toLocaleString() : '—';
    return `<tr>
      <td class="date-cell">${ts}</td>
      <td><span class="log-action ${meta.cls}">${meta.label}</span></td>
      <td style="font-family:var(--font-mono);font-size:11px">${redactEmail(e.actor)}</td>
      <td style="font-family:var(--font-mono);font-size:11px;color:var(--blue)">${redactEmail(e.target)}</td>
      <td style="font-size:11px;color:var(--muted);max-width:280px;word-break:break-word;white-space:normal">${escHtml(e.detail || '—')}</td>
    </tr>`;
  }).join('');

  const pag = document.getElementById('logPagination');
  if (totalPages <= 1) { pag.innerHTML = ''; return; }
  const nums = getPageNums(logPage, totalPages);
  let html = `<button class="page-btn" onclick="goLogPage(${logPage-1})" ${logPage===1?'disabled':''}>‹ Prev</button>`;
  let prev = null;
  for (const p of nums) {
    if (prev !== null && p - prev > 1) html += `<span class="page-ellipsis">…</span>`;
    html += `<button class="page-btn ${p===logPage?'active':''}" onclick="goLogPage(${p})">${p}</button>`;
    prev = p;
  }
  html += `<button class="page-btn" onclick="goLogPage(${logPage+1})" ${logPage===totalPages?'disabled':''}>Next ›</button>`;
  html += `<span style="display:flex;align-items:center;gap:6px;margin-left:8px;">
    <span style="font-size:11px;color:var(--muted);font-family:var(--font-ui);">Page</span>
    <input type="number" min="1" max="${totalPages}" value="${logPage}"
      onchange="goLogPage(parseInt(this.value))"
      onkeydown="if(event.key==='Enter') goLogPage(parseInt(this.value))"
      style="width:54px;background:var(--surface2);border:1px solid var(--border2);border-radius:3px;color:var(--text);font-family:var(--font-mono);font-size:12px;padding:5px 8px;outline:none;text-align:center;"/>
    <span style="font-size:11px;color:var(--muted);font-family:var(--font-ui);">of ${totalPages}</span>
  </span>`;
  pag.innerHTML = html;
}

function goLogPage(p) {
  const totalPages = Math.ceil(allLogs.length / LOG_PAGE_SIZE);
  if (p < 1 || p > totalPages || isNaN(p)) return;
  logPage = p;
  renderLogs();
  document.getElementById('tabLogsPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function approveUser(email) {
  const r = await apiFetch(`/admin/users/${encodeURIComponent(email)}/approve`, { method:'POST' });
  if (r) { toast(`${email} approved`, 'success'); loadUsers(); }
}
async function rejectUser(email) {
  const r = await apiFetch(`/admin/users/${encodeURIComponent(email)}/reject`, { method:'POST' });
  if (r) { toast(`${email} rejected`, 'success'); loadUsers(); }
}
async function promoteUser(email) {
  const r = await apiFetch(`/admin/users/${encodeURIComponent(email)}/promote`, { method:'POST' });
  if (r) { toast(`${email} promoted`, 'success'); loadUsers(); }
}
async function demoteUser(email) {
  if (!confirm(`Remove admin from ${email}?`)) return;
  const r = await apiFetch(`/admin/users/${encodeURIComponent(email)}/demote`, { method:'POST' });
  if (r) { toast(`${email} demoted`, 'success'); loadUsers(); }
}
async function removeUser(email) {
  if (!confirm(`Permanently remove ${email}?`)) return;
  const r = await apiFetch(`/admin/users/${encodeURIComponent(email)}`, { method:'DELETE' });
  if (r) { toast(`${email} removed`, 'success'); loadUsers(); }
}

let resetTargetEmail = null;
function openResetModal(email) {
  resetTargetEmail = email;
  document.getElementById('resetModalSub').textContent  = `Set a new password for ${email}`;
  document.getElementById('resetPasswordInput').value   = '';
  document.getElementById('resetPasswordConfirm').value = '';
  document.getElementById('resetModal').classList.add('open');
}
async function submitResetPassword() {
  const pw  = document.getElementById('resetPasswordInput').value;
  const pw2 = document.getElementById('resetPasswordConfirm').value;
  if (!pw)           return toast('Enter a password', 'error');
  if (pw.length < 6) return toast('Min 6 characters', 'error');
  if (pw !== pw2)    return toast('Passwords do not match', 'error');
  const r = await apiFetch(`/admin/users/${encodeURIComponent(resetTargetEmail)}/reset-password`, {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ new_password: pw })
  });
  if (r) {
    toast(`Password reset for ${resetTargetEmail}`, 'success');
    document.getElementById('resetModal').classList.remove('open');
    resetTargetEmail = null;
  }
}

document.getElementById('bulkEditModal').addEventListener('click', e => { if (e.target === e.currentTarget) e.currentTarget.classList.remove('open'); });
document.getElementById('editModal').addEventListener('click', e => { if (e.target === e.currentTarget) e.currentTarget.classList.remove('open'); });
document.getElementById('resetModal').addEventListener('click', e => { if (e.target === e.currentTarget) e.currentTarget.classList.remove('open'); });

// ═══════════════════════════════════════════════════════════
// GROUP BANS
// ═══════════════════════════════════════════════════════════
let fullGroupList = [], filteredGroups = [], groupPage = 1;
const GROUP_PAGE_SIZE = 25;
let selectedGroups = new Set(), groupEditTarget = null;

async function loadGroups() {
  const r = await apiFetch('/groups', {}, false);
  if (!r) return;
  fullGroupList = [...(r.groups || [])].reverse().map(g => ({ ...g, rawMessage: g.message }));
  applyGroupFilter();
}

function applyGroupFilter() {
  const q   = document.getElementById('searchInput').value.toLowerCase().trim();
  const cat = document.getElementById('categoryFilter').value;
  filteredGroups = fullGroupList.filter(g => {
    const cached = groupCache[g.groupId];
    const matchQ = !q || g.groupId.includes(q) || g.message.toLowerCase().includes(q) || (cached?.name || '').toLowerCase().includes(q);
    const matchC = !cat || getTag(g.rawMessage || g.message) === cat;
    return matchQ && matchC;
  });
  groupPage = 1;
  document.getElementById('groupShowingCount').textContent = filteredGroups.length;
  renderGroups();
}

const groupCache = {};

async function fetchGroupInfo(groupIds) {
  const missing = groupIds.filter(id => !groupCache[id]);
  if (!missing.length) return;
  for (const id of missing) groupCache[id] = { name: null, iconUrl: null };
  await Promise.all(missing.map(async id => {
    try {
      const r = await fetch(`https://groups.roproxy.com/v1/groups/${id}`);
      if (!r.ok) return;
      const data = await r.json();
      groupCache[id].name = data.name || null;
    } catch {}
    try {
      const r = await fetch(`https://thumbnails.roproxy.com/v1/groups/icons?groupIds=${id}&size=150x150&format=Png`);
      if (!r.ok) return;
      const data = await r.json();
      const thumb = data?.data?.[0];
      if (thumb?.imageUrl) groupCache[id].iconUrl = thumb.imageUrl;
    } catch {}
  }));
}

function renderGroups() {
  const tbody      = document.getElementById('groupBody');
  const totalPages = Math.max(1, Math.ceil(filteredGroups.length / GROUP_PAGE_SIZE));
  if (groupPage > totalPages) groupPage = totalPages;
  const slice = filteredGroups.slice((groupPage - 1) * GROUP_PAGE_SIZE, groupPage * GROUP_PAGE_SIZE);
  if (!slice.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty">No groups found.</td></tr>`;
    document.getElementById('groupPagination').innerHTML = '';
    return;
  }
  tbody.innerHTML = slice.map(g => {
    const tag    = getTag(g.rawMessage || g.message);
    const label  = TAG_LABELS[tag] || 'Other';
    const reason = cleanMessage(g.message);
    const date   = formatDate(g.date);
    const checked = selectedGroups.has(g.groupId) ? 'checked' : '';
    const info   = groupCache[g.groupId];
    const checkTd = currentUser
      ? `<td style="padding:10px 12px;width:36px;"><input type="checkbox" class="grp-check" data-id="${escHtml(g.groupId)}" onchange="onGroupCheck()" ${checked} style="cursor:pointer;accent-color:var(--red);"></td>`
      : '<td style="width:0;padding:0;overflow:hidden;"></td>';
    const actions = currentUser ? `
      <td class="action-btns">
        <button class="edit-btn" onclick="openGroupEditModal('${escHtml(g.groupId)}','${escHtml(g.message).replace(/'/g,"\\'")}')">Edit</button>
        <button class="unban-btn" onclick="removeGroupBan('${escHtml(g.groupId)}')">Unban</button>
      </td>` : '<td></td>';
    const avatarHtml = info?.iconUrl
      ? `<img src="${escHtml(info.iconUrl)}" alt="" style="width:100%;height:100%;object-fit:cover;display:block;"/>`
      : info === undefined ? '🏢' : '';
    const nameHtml = escHtml(info?.name || 'Group');
    return `<tr>
      ${checkTd}
      <td><div style="display:flex;align-items:center;gap:10px;">
        <div class="player-avatar${!info?.iconUrl ? ' loading' : ''}" id="gav-${g.groupId}" style="pointer-events:none">${avatarHtml}</div>
        <div class="player-info">
          <span id="gnm-${g.groupId}" style="font-weight:600;font-size:13px;color:var(--text);">${escHtml(nameHtml)}</span>
          <span style="font-family:var(--font-mono);font-size:11px;color:var(--muted);">ID: ${g.groupId}</span>
        </div>
      </div></td>
      <td style="font-family:var(--font-mono);font-size:11px;">${g.groupId}</td>
      <td><span class="tag tag-${tag}">${label}</span></td>
      <td style="font-size:12px;color:var(--text);word-break:break-word;white-space:normal">${escHtml(reason)}</td>
      <td style="font-family:var(--font-mono);font-size:11px;color:var(--muted)">${escHtml(g.bannedBy || '—')}</td>
      <td class="date-cell">${date}</td>
      ${actions}
    </tr>`;
  }).join('');
  renderGroupPagination(totalPages);
  const uncached = slice.map(g => g.groupId).filter(id => !groupCache[id]);
  if (uncached.length) {
    fetchGroupInfo(uncached).then(() => {
      for (const g of slice) {
        const info = groupCache[g.groupId];
        if (!info) continue;
        const avEl = document.getElementById(`gav-${g.groupId}`);
        const nmEl = document.getElementById(`gnm-${g.groupId}`);
        if (avEl) {
          avEl.classList.remove('loading');
          if (info.iconUrl) avEl.innerHTML = `<img src="${escHtml(info.iconUrl)}" alt="" style="width:100%;height:100%;object-fit:cover;display:block;"/>`;
          avEl.removeAttribute('id');
        }
        if (nmEl) { if (info.name) nmEl.textContent = info.name; nmEl.removeAttribute('id'); }
      }
    });
  }
}

function renderGroupPagination(totalPages) {
  const pag = document.getElementById('groupPagination');
  if (totalPages <= 1) { pag.innerHTML = ''; return; }
  const nums = getPageNums(groupPage, totalPages);
  let html = `<button class="page-btn" onclick="goGroupPage(${groupPage-1})" ${groupPage===1?'disabled':''}>‹ Prev</button>`;
  let prev = null;
  for (const p of nums) {
    if (prev !== null && p - prev > 1) html += `<span class="page-ellipsis">…</span>`;
    html += `<button class="page-btn ${p===groupPage?'active':''}" onclick="goGroupPage(${p})">${p}</button>`;
    prev = p;
  }
  html += `<button class="page-btn" onclick="goGroupPage(${groupPage+1})" ${groupPage===totalPages?'disabled':''}>Next ›</button>`;
  html += `<span style="display:flex;align-items:center;gap:6px;margin-left:8px;">
    <span style="font-size:11px;color:var(--muted);font-family:var(--font-ui);">Page</span>
    <input type="number" min="1" max="${totalPages}" value="${groupPage}"
      onchange="goGroupPage(parseInt(this.value))"
      onkeydown="if(event.key==='Enter') goGroupPage(parseInt(this.value))"
      style="width:54px;background:var(--surface2);border:1px solid var(--border2);border-radius:3px;color:var(--text);font-family:var(--font-mono);font-size:12px;padding:5px 8px;outline:none;text-align:center;"/>
    <span style="font-size:11px;color:var(--muted);font-family:var(--font-ui);">of ${totalPages}</span>
  </span>`;
  pag.innerHTML = html;
}

function goGroupPage(p) {
  const totalPages = Math.ceil(filteredGroups.length / GROUP_PAGE_SIZE);
  if (p < 1 || p > totalPages || isNaN(p)) return;
  groupPage = p;
  renderGroups();
}

function getSelectedGroupIds() {
  return [...document.querySelectorAll('.grp-check:checked')].map(cb => cb.dataset.id);
}

function onGroupCheck() {
  const ids = getSelectedGroupIds();
  const bar = document.getElementById('groupBulkBar');
  bar.style.display = ids.length ? 'flex' : 'none';
  document.getElementById('groupBulkCount').textContent = `${ids.length} group${ids.length !== 1 ? 's' : ''} selected`;
  ids.forEach(id => selectedGroups.add(id));
  document.querySelectorAll('.grp-check:not(:checked)').forEach(cb => selectedGroups.delete(cb.dataset.id));
}

function clearGroupSelection() {
  document.querySelectorAll('.grp-check').forEach(el => el.checked = false);
  selectedGroups.clear();
  document.getElementById('groupBulkBar').style.display = 'none';
}

function localRemoveGroups(groupIds) {
  const idSet = new Set(groupIds);
  fullGroupList = fullGroupList.filter(g => !idSet.has(g.groupId));
  applyGroupFilter();
}

function localAddGroups(entries) {
  for (const e of entries) {
    if (!fullGroupList.find(g => g.groupId === e.groupId)) fullGroupList.unshift(e);
  }
  applyGroupFilter();
}

function localEditGroups(groupIds, message) {
  const idSet = new Set(groupIds);
  for (const g of fullGroupList) {
    if (idSet.has(g.groupId)) { g.rawMessage = message; g.message = message; }
  }
  applyGroupFilter();
}

// ── RULES AGREEMENT ───────────────────────────────────────────────────────────
let _rulesAgreed = false;

function agreeToRules() {
  _rulesAgreed = true;
  document.getElementById('rulesPanel').style.setProperty('display', 'none', 'important');
  const activeTab = document.querySelector('.tab.active');
  if (activeTab) activeTab.click();
}

function hasAgreedToRules() { return _rulesAgreed; }

function showStaffPanels() {
  if (!_rulesAgreed) {
    document.getElementById('rulesPanel').style.setProperty('display', 'block', 'important');
    document.getElementById('adminPanel').style.setProperty('display', 'none', 'important');
    document.getElementById('groupAdminPanel').style.setProperty('display', 'none', 'important');
  } else {
    document.getElementById('rulesPanel').style.setProperty('display', 'none', 'important');
    const activeTab = document.querySelector('.tab.active');
    if (activeTab) activeTab.click();
  }
}

function updateGroupBanBtn() {
  const cat = document.getElementById('inGroupCategory')?.value;
  const btn = document.getElementById('groupBanBtn');
  if (!btn) return;
  const allowed = cat === 'Safety Issue';
  btn.disabled       = !allowed;
  btn.style.opacity  = allowed ? '1' : '0.35';
  btn.style.cursor   = allowed ? 'pointer' : 'not-allowed';
  btn.title = allowed ? '' : 'Group bans are only allowed for Safety Issue category';
}

// ── Group CRUD ────────────────────────────────────────────────────────────────
async function addGroupBan() {
  const rawIds   = document.getElementById('inGroupId').value.trim();
  const reason   = document.getElementById('inGroupReason').value.trim();
  const category = document.getElementById('inGroupCategory').value;
  if (!rawIds || !reason) return toast('Fill in Group ID and Reason', 'error');
  if (category !== 'Safety Issue') return toast('Group bans are only allowed for Safety Issue category', 'error');
  const groupIds = rawIds.split(',').map(id => id.trim()).filter(Boolean);
  const message  = `[${category}] ${reason}`;
  const btn = document.getElementById('groupBanBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="btn-spinner"></span>Banning...';
  const r = await apiFetch('/groups/bulk', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ groupIds, message }) });
  btn.disabled = false;
  btn.innerHTML = '+ Ban Group';
  updateGroupBanBtn();
  if (!r) return;
  const added = r.added || [], skipped = r.skipped || [];
  if (added.length) toast(`Banned ${added.length} group${added.length > 1 ? 's' : ''}${skipped.length ? `, ${skipped.length} already banned` : ''}`, 'success');
  else toast(`All groups already banned`, 'error');
  document.getElementById('inGroupId').value = '';
  document.getElementById('inGroupReason').value = '';
  const today = new Date().toISOString().split('T')[0];
  localAddGroups(added.map(gid => ({ groupId: gid, message, rawMessage: message, date: today, bannedBy: currentUser?.username || 'unknown' })));
}

async function removeGroupBan(groupId) {
  if (!confirm(`Unban group ${groupId}?`)) return;
  const btn = document.querySelector(`.unban-btn[onclick="removeGroupBan('${groupId}')"]`);
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="btn-spinner"></span>'; }
  const r = await apiFetch(`/groups/${groupId}`, { method: 'DELETE' });
  if (btn) { btn.disabled = false; btn.innerHTML = 'Unban'; }
  if (!r) return;
  toast(`Group ${groupId} unbanned`, 'success');
  localRemoveGroups([groupId]);
}

async function bulkUnbanGroups() {
  const ids = getSelectedGroupIds();
  if (!ids.length) return;
  if (!confirm(`Unban ${ids.length} group${ids.length !== 1 ? 's' : ''}?`)) return;
  const btn = document.querySelector('#groupBulkBar .btn-red');
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="btn-spinner"></span>Unbanning...'; }
  const r = await apiFetch('/groups/bulk-remove', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ groupIds: ids }) });
  if (btn) { btn.disabled = false; btn.innerHTML = 'Unban Selected'; }
  if (!r) return;
  toast(`Unbanned ${r.removed || ids.length} group${ids.length !== 1 ? 's' : ''}`, 'success');
  clearGroupSelection();
  localRemoveGroups(ids);
}

function openGroupEditModal(groupId, currentMessage) {
  groupEditTarget = groupId;
  const cats = { 'exploit':'Exploit','safety':'Safety Issue','bypass':'Bypass','bot':'Bot','allegations':'Allegations','stolen':'Stolen Assets','abuse':'Abuse','general':'General' };
  const tag    = getTag(currentMessage);
  const reason = cleanMessage(currentMessage);
  const sel    = document.getElementById('groupEditCategory');
  for (const opt of sel.options) opt.selected = opt.value === (cats[tag] || 'General');
  document.getElementById('groupEditReasonInput').value = reason;
  document.getElementById('groupEditModal').classList.add('open');
}

async function submitGroupEditReason() {
  const reason   = document.getElementById('groupEditReasonInput').value.trim();
  const category = document.getElementById('groupEditCategory').value;
  if (!reason) return toast('Reason cannot be empty', 'error');
  const message = `[${category}] ${reason}`;
  const btn = document.getElementById('groupEditBtn');
  btn.disabled = true; btn.innerHTML = '<span class="btn-spinner"></span>Saving...';
  const r = await apiFetch(`/groups/${groupEditTarget}`, { method: 'PATCH', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ message }) });
  btn.disabled = false; btn.innerHTML = 'Save Changes';
  if (!r) return;
  toast('Group ban reason updated', 'success');
  document.getElementById('groupEditModal').classList.remove('open');
  localEditGroups([groupEditTarget], message);
  groupEditTarget = null;
}

function openGroupBulkEditModal() {
  const ids = getSelectedGroupIds();
  if (!ids.length) return;
  document.getElementById('groupBulkEditSub').textContent = `Updating reason for ${ids.length} group${ids.length !== 1 ? 's' : ''}.`;
  document.getElementById('groupBulkEditReasonInput').value = '';
  document.getElementById('groupBulkEditModal').classList.add('open');
  setTimeout(() => document.getElementById('groupBulkEditReasonInput').focus(), 50);
}

async function submitGroupBulkEdit() {
  const ids      = getSelectedGroupIds();
  const reason   = document.getElementById('groupBulkEditReasonInput').value.trim();
  const category = document.getElementById('groupBulkEditCategory').value;
  if (!reason) return toast('Reason cannot be empty', 'error');
  const message = `[${category}] ${reason}`;
  const btn = document.getElementById('groupBulkEditBtn');
  btn.disabled = true; btn.innerHTML = '<span class="btn-spinner"></span>Saving...';
  const r = await apiFetch('/groups/bulk-edit', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ groupIds: ids, message }) });
  btn.disabled = false; btn.innerHTML = 'Save Changes';
  if (!r) return;
  toast(`Updated reason for ${r.updated || ids.length} group${ids.length !== 1 ? 's' : ''}`, 'success');
  document.getElementById('groupBulkEditModal').classList.remove('open');
  clearGroupSelection();
  localEditGroups(ids, message);
}

document.getElementById('groupEditModal').addEventListener('click', e => { if (e.target === e.currentTarget) e.currentTarget.classList.remove('open'); });
document.getElementById('groupBulkEditModal').addEventListener('click', e => { if (e.target === e.currentTarget) e.currentTarget.classList.remove('open'); });

function switchTab(tab, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tabBans').style.display        = tab === 'bans'   ? '' : 'none';
  document.getElementById('tabGroupsPanel').style.display = tab === 'groups' ? '' : 'none';
  document.getElementById('tabUsersPanel').style.display  = tab === 'users'  ? '' : 'none';
  document.getElementById('tabLogsPanel').style.display   = tab === 'logs'   ? '' : 'none';
  const isLoggedIn = !!currentUser;
  const agreed     = hasAgreedToRules();
  document.getElementById('rulesPanel').style.setProperty('display', (isLoggedIn && !agreed) ? 'block' : 'none', 'important');
  document.getElementById('adminPanel').style.setProperty('display', (isLoggedIn && agreed && tab === 'bans')   ? 'block' : 'none', 'important');
  document.getElementById('groupAdminPanel').style.setProperty('display', (isLoggedIn && agreed && tab === 'groups') ? 'block' : 'none', 'important');
  if (tab === 'groups') { loadGroups(); updateGroupBanBtn(); }
  if (tab === 'users')  loadUsers();
  if (tab === 'logs')   loadLogs();
}

// ── API HELPER ────────────────────────────────────────────────────────────────
async function apiFetch(path, opts = {}, withAuth = true) {
  const headers = { ...(opts.headers || {}) };
  try {
    const res  = await fetch(API + path, { ...opts, headers, credentials: 'same-origin' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = Array.isArray(data.detail)
        ? data.detail.map(e => e.msg).join(', ')
        : (data.detail || 'Error');
      toast(msg, 'error');
      return null;
    }
    return data;
  } catch {
    toast('Cannot reach server', 'error');
    return null;
  }
}

// ── TOAST ────────────────────────────────────────────────────────────────────
function toast(msg, type = '') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'show ' + type;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.className = '', 3000);
}

// ── STAT CARD FILTER ─────────────────────────────────────────────────────────
function isGroupTab() {
  return document.getElementById('tabGroupsPanel').style.display !== 'none';
}

function handleSearch() {
  if (isGroupTab()) applyGroupFilter();
  else applyFilter();
}

function filterByStatCard(card) {
  const filter      = card.dataset.filter;
  const select      = document.getElementById('categoryFilter');
  const isActive    = card.classList.contains('active');
  const isTotalCard = filter === '';
  document.querySelectorAll('.stat-card[data-filter]').forEach(c => c.classList.remove('active'));
  if (!isTotalCard && !isActive) {
    card.classList.add('active');
    select.value = filter;
  } else {
    select.value = '';
    var _sc = document.querySelector('.stat-card[data-filter=""]'); if (_sc) _sc.classList.add('active');
  }
  if (isGroupTab()) {
    applyGroupFilter();
    window.scrollTo({ top: document.getElementById('tabGroupsPanel').offsetTop - 60, behavior: 'smooth' });
  } else {
    applyFilter();
    window.scrollTo({ top: document.getElementById('tabBans').offsetTop - 60, behavior: 'smooth' });
  }
}

document.getElementById('categoryFilter').addEventListener('change', () => {
  const val = document.getElementById('categoryFilter').value;
  document.querySelectorAll('.stat-card[data-filter]').forEach(c => {
    c.classList.toggle('active', c.dataset.filter === val);
  });
  if (!val) { var _sc2 = document.querySelector('.stat-card[data-filter=""]'); if (_sc2) _sc2.classList.add('active'); }
  if (isGroupTab()) applyGroupFilter();
  else applyFilter();
});

// ── COPY SCRIPT ───────────────────────────────────────────────────────────────
const GBS_SCRIPT_URL = '';
let _rawScriptText = `-- Moderation Registry sample
-- Fetches user and group bans, then backs up both tables in DataStore.
-- Replace the URLs with URLs your Roblox server can reach.

local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local DataStoreService = game:GetService("DataStoreService")

local USER_BANS_URL = "http://127.0.0.1:2949/BannedUsers.json"
local GROUP_BANS_URL = "http://127.0.0.1:2949/BannedGroups.json"
local BACKUP_STORE = DataStoreService:GetDataStore("ModerationRegistryBackup")

local USER_BACKUP_KEY = "BannedUsers"
local GROUP_BACKUP_KEY = "BannedGroups"

local function countKeys(dictionary)
    local count = 0
    for _ in pairs(dictionary) do
        count += 1
    end
    return count
end

local function recordsToLookup(records, idField)
    local lookup = {}
    for _, record in ipairs(records or {}) do
        local id = record[idField]
        if id then
            lookup[tostring(id)] = record.message or "Removed from this experience"
        end
    end
    return lookup
end

local function readBackup(key, idField, label)
    local ok, records = pcall(function()
        return BACKUP_STORE:GetAsync(key)
    end)
    if ok and type(records) == "table" then
        warn("Using cached moderation registry backup for", label)
        return recordsToLookup(records, idField)
    end
    warn("Moderation registry unavailable and no backup was found for", label)
    return {}
end

local function writeBackup(key, records)
    task.spawn(function()
        local ok, err = pcall(function()
            BACKUP_STORE:SetAsync(key, records)
        end)
        if not ok then
            warn("Failed to update moderation registry backup:", err)
        end
    end)
end

local function loadRecords(url, backupKey, idField, label)
    local ok, body = pcall(function()
        return HttpService:GetAsync(url, true)
    end)
    if not ok then
        return readBackup(backupKey, idField, label)
    end
    local decoded, records = pcall(function()
        return HttpService:JSONDecode(body)
    end)
    if not decoded or type(records) ~= "table" then
        return readBackup(backupKey, idField, label)
    end
    writeBackup(backupKey, records)
    return recordsToLookup(records, idField)
end

local userBans = loadRecords(USER_BANS_URL, USER_BACKUP_KEY, "userId", "users")
local groupBans = loadRecords(GROUP_BANS_URL, GROUP_BACKUP_KEY, "groupId", "groups")
print("Moderation Registry loaded", countKeys(userBans), "user bans and", countKeys(groupBans), "group bans")

local function getGroupBanReason(player)
    for groupId, reason in pairs(groupBans) do
        local numericGroupId = tonumber(groupId)
        if numericGroupId and player:IsInGroup(numericGroupId) then
            return reason
        end
    end
    return nil
end

local function checkPlayer(player)
    print("Moderation Registry checking", player.Name, player.UserId)
    local reason = userBans[tostring(player.UserId)] or getGroupBanReason(player)
    if reason then
        player:Kick(reason)
    end
end

Players.PlayerAdded:Connect(checkPlayer)

for _, player in ipairs(Players:GetPlayers()) do
    task.defer(checkPlayer, player)
end`;

function copyScript() {
  if (!_rawScriptText) return toast('Script not loaded yet', 'error');
  navigator.clipboard.writeText(_rawScriptText).then(() => {
    const btn = document.getElementById('copyBtn');
    btn.textContent = 'Copied!';
    btn.style.borderColor = 'var(--green)';
    btn.style.color = 'var(--green)';
    setTimeout(() => {
      btn.textContent = 'Copy';
      btn.style.borderColor = 'var(--border2)';
      btn.style.color = 'var(--muted)';
    }, 2000);
  });
}

document.addEventListener('DOMContentLoaded', async function() {
  const el = document.getElementById('scriptCode');
  if (!el) return;
  if (!GBS_SCRIPT_URL) {
    el.textContent = _rawScriptText;
    if (typeof hljs !== 'undefined') hljs.highlightElement(el);
    return;
  }
  try {
    const res = await fetch(GBS_SCRIPT_URL);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    _rawScriptText = await res.text();
    el.textContent = _rawScriptText;
    if (typeof hljs !== 'undefined') hljs.highlightElement(el);
  } catch(e) {
    el.textContent = `-- Failed to load script: ${e.message}`;
  }
});

// ── Console warning ───────────────────────────────────────────────────────────
function _showConsoleWarning() {
  console.log('%c⚠ Hold Up!', 'color:#e03030;font-size:64px;font-weight:900;');
  console.log('%cIf someone told you to copy/paste something here, you are almost certainly being scammed.', 'color:#ffffff;font-size:16px;font-weight:600;');
  console.log('%cPasting anything here could give attackers full access to your account, ban list, and staff panel.', 'color:#e03030;font-size:14px;font-weight:700;');
  console.log('%cIf you are a developer and know what you are doing, carry on.', 'color:#5a6070;font-size:12px;');
}
_showConsoleWarning();
setTimeout(_showConsoleWarning, 500);
setTimeout(_showConsoleWarning, 2000);

init();
