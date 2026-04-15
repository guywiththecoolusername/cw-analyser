// ══════════════════════════════════════════════
//  STATE & GLOBALS
// ══════════════════════════════════════════════
let loadedFiles = [];
let list = [];
let notInList = [];
let pendingPromote = null;
let activeFilter = 'all';
let isReadOnly = false;
let titleLang = 'ro'; 

const AL_CLIENT_ID = '39139'; // Hardcoded as requested
const MAL_CLIENT_ID = '52944d3920b9e1037149d2e207849e57'; // <-- Fill in your MAL client ID
const PREFIXES = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const SHARE_WORKER_URL = 'https://cw-sharer.mynameismythpat.workers.dev';
const WORKER = SHARE_WORKER_URL.replace(/\/+$/, '');

const dbById = new Map(), dbByMalId = new Map(), dbByTitle = new Map();
let dbLoaded = false;
let connectedAccount = null; 

// Start processes immediately
const dbReady = loadDB();
checkOAuthCallback();
checkShareUrl();

// ══════════════════════════════════════════════
//  OAUTH CALLBACK HANDLER
// ══════════════════════════════════════════════
function checkOAuthCallback() {
  // AniList uses implicit flow — token comes back in the URL hash
  const hash = window.location.hash.substring(1);
  const hashParams = new URLSearchParams(hash);
  const alToken = hashParams.get('access_token');
  if (alToken) {
    localStorage.setItem('anilist_token', alToken);
    window.history.replaceState(null, null, window.location.pathname);
    verifyAniListToken(alToken);
    return;
  }

  // MAL uses PKCE authorization code flow — code comes back as a query param
  const urlParams = new URLSearchParams(window.location.search);
  const malCode = urlParams.get('code');
  const malState = urlParams.get('state');
  if (malCode && malState === sessionStorage.getItem('mal_state')) {
    window.history.replaceState(null, null, window.location.pathname);
    exchangeMalCode(malCode);
    return;
  }

  // Normal startup — check for saved tokens
  const savedAlToken = localStorage.getItem('anilist_token');
  if (savedAlToken) verifyAniListToken(savedAlToken);

  const savedMalToken = localStorage.getItem('mal_token');
  if (savedMalToken) verifyMalToken(savedMalToken);
}

async function verifyAniListToken(token) {
  try {
    const r = await fetch('https://graphql.anilist.co/',{
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':`Bearer ${token}`},
      body:JSON.stringify({query:'query{Viewer{name}}'})
    });
    if (r.status === 401) { 
      localStorage.removeItem('anilist_token'); 
      return; 
    }
    const {data} = await r.json();
    const username = data?.Viewer?.name ?? 'AniList';
    setConnected({type:'anilist', username, token, viewOnly:false});
    showAniListConnected(username);
  } catch (e) {
    console.error('AL Verify Error', e);
  }
}

function showAniListConnected(username) {
  document.getElementById('al-disconnected-row').style.display = 'none';
  const connRow = document.getElementById('al-connected-row');
  connRow.style.display = 'flex';
  document.getElementById('al-connected-name').textContent = `Connected as ${username}`;
  document.getElementById('al-not-you-wrap').style.display = 'block';
  // Enable the main go button only if the user hasn't loaded files separately
  document.getElementById('go-btn').disabled = loadedFiles.filter(f => f.type !== 'unknown').length === 0;
}

async function analyseAniList() {
  if (!connectedAccount?.token) { showToast('No token — reconnect'); return; }
  const btn = document.getElementById('al-analyse-btn');
  if (btn) { btn.textContent = '…'; btn.disabled = true; }
  try {
    await fetchAniListByUser(connectedAccount.username, false, connectedAccount.token);
    buildDashboard();
  } catch(e) {
    showToast('❌ ' + e.message);
  } finally {
    if (btn) { btn.textContent = 'Analyse list →'; btn.disabled = false; }
  }
}

function anilistDisconnect() {
  localStorage.removeItem('anilist_token');
  setConnected(null);
  document.getElementById('al-disconnected-row').style.display = 'flex';
  document.getElementById('al-connected-row').style.display = 'none';
  document.getElementById('al-not-you-wrap').style.display = 'none';
  // Remove any previously loaded AL items
  loadedFiles = loadedFiles.filter(f => !f._external);
  assignPrefixes(); renderFileList();
  document.getElementById('go-btn').disabled = loadedFiles.filter(f => f.type !== 'unknown').length === 0;
}

// ══════════════════════════════════════════════
//  MAL OAUTH2 (PKCE)
// ══════════════════════════════════════════════
function connectMALImport() {
  // Generate PKCE code_verifier (plain method — MAL supports it, no SHA256 needed)
  const verifier = generateCodeVerifier();
  const state = generateCodeVerifier(16);
  sessionStorage.setItem('mal_verifier', verifier);
  sessionStorage.setItem('mal_state', state);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: MAL_CLIENT_ID,
    code_challenge: verifier,         // plain: challenge === verifier
    code_challenge_method: 'plain',
    state,
    redirect_uri: window.location.origin + window.location.pathname,
  });
  window.location.href = `https://myanimelist.net/v1/oauth2/authorize?${params}`;
}

function generateCodeVerifier(len = 64) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => chars[b % chars.length]).join('');
}

async function exchangeMalCode(code) {
  const verifier = sessionStorage.getItem('mal_verifier');
  if (!verifier) { showToast('❌ MAL: Missing code verifier — try again'); return; }
  sessionStorage.removeItem('mal_verifier');
  sessionStorage.removeItem('mal_state');
  try {
    // Token exchange must go through our worker — MAL token endpoint has no CORS headers
    const r = await fetch(`${WORKER}/mal-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: MAL_CLIENT_ID,
        code,
        code_verifier: verifier,
        redirect_uri: window.location.origin + window.location.pathname,
      }),
    });
    if (!r.ok) throw new Error(`Token exchange failed (${r.status})`);
    const { access_token, refresh_token } = await r.json();
    if (!access_token) throw new Error('No access token returned');
    localStorage.setItem('mal_token', access_token);
    if (refresh_token) localStorage.setItem('mal_refresh_token', refresh_token);
    verifyMalToken(access_token);
  } catch (e) {
    showToast('❌ MAL: ' + e.message);
  }
}

async function verifyMalToken(token) {
  try {
    const r = await fetch(`${WORKER}/mal-proxy?url=${encodeURIComponent('https://api.myanimelist.net/v2/users/@me')}`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    if (r.status === 401) { localStorage.removeItem('mal_token'); return; }
    const data = await r.json();
    const username = data.name ?? 'MAL User';
    setConnected({ type: 'mal', username, token, viewOnly: false });
    showMalConnected(username);
  } catch (e) { console.error('MAL verify error', e); }
}

function showMalConnected(username) {
  const disRow = document.getElementById('mal-disconnected-row');
  const conRow = document.getElementById('mal-connected-row');
  const notYou = document.getElementById('mal-not-you-wrap');
  const nameEl = document.getElementById('mal-connected-name');
  if (disRow) disRow.style.display = 'none';
  if (conRow) conRow.style.display = 'flex';
  if (nameEl) nameEl.textContent = `Connected as ${username}`;
  if (notYou) notYou.style.display = 'block';
}

async function analyseMAL() {
  if (!connectedAccount?.token || connectedAccount.type !== 'mal') { showToast('No MAL token'); return; }
  const btn = document.getElementById('mal-analyse-btn');
  if (btn) { btn.textContent = '…'; btn.disabled = true; }
  try {
    await fetchMALByToken(connectedAccount.token);
    buildDashboard();
  } catch (e) {
    showToast('❌ MAL: ' + e.message);
  } finally {
    if (btn) { btn.textContent = 'Analyse list →'; btn.disabled = false; }
  }
}

function malDisconnect() {
  localStorage.removeItem('mal_token');
  localStorage.removeItem('mal_refresh_token');
  setConnected(null);
  const dis = document.getElementById('mal-disconnected-row');
  const con = document.getElementById('mal-connected-row');
  const notYou = document.getElementById('mal-not-you-wrap');
  if (dis) dis.style.display = 'flex';
  if (con) con.style.display = 'none';
  if (notYou) notYou.style.display = 'none';
  loadedFiles = loadedFiles.filter(f => !f._external);
  assignPrefixes(); renderFileList();
  document.getElementById('go-btn').disabled = loadedFiles.filter(f => f.type !== 'unknown').length === 0;
}

async function fetchMALByToken(token) {
  const fields = [
    'id','title','main_picture','alternative_titles','num_episodes',
    'genres','media_type','start_date','studios',
    'my_list_status{status,score,num_episodes_watched,is_rewatching,start_date,finish_date}',
  ].join(',');
  const items = [];
  let url = `https://api.myanimelist.net/v2/users/@me/animelist?fields=${encodeURIComponent(fields)}&limit=1000&sort=list_updated_at`;

  while (url) {
    const r = await fetch(`${WORKER}/mal-proxy?url=${encodeURIComponent(url)}`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    if (r.status === 401) {
      localStorage.removeItem('mal_token');
      throw new Error('Token expired — please reconnect');
    }
    if (!r.ok) throw new Error(`MAL API error ${r.status}`);
    const json = await r.json();

    (json.data ?? []).forEach(({ node: a }) => {
      const st = a.my_list_status ?? {};
      const pic = a.main_picture;
      const mainStudio = a.studios?.[0]?.name ?? null;
      items.push({
        _id: String(a.id), slug: null, episodeId: null,
        malId: String(a.id), anilistId: null,
        title: a.title ?? null,
        titleJp: a.alternative_titles?.ja ?? null,
        titleEn: a.alternative_titles?.en ?? null,
        titleRo: a.title ?? null,
        thumb: pic?.large ?? pic?.medium ?? null,
        banner: pic?.large ?? pic?.medium ?? null,
        url: `https://myanimelist.net/anime/${a.id}`,
        epCur: st.num_episodes_watched ?? null,
        epTot: a.num_episodes || null,
        epSub: null, epDub: null, epWatched: st.num_episodes_watched ?? null,
        timeCur: null, timeTot: null, timeCurSec: 0, timeTotSec: 0, prog: null,
        status: malStatus(st.status ?? ''),
        score: st.score || null,
        startDate: st.start_date ?? null,
        finishDate: st.finish_date ?? null,
        rewatching: st.is_rewatching ?? false,
        rank: null, rankLabel: null, prefix: null,
        fromCw: false, fromWl: true,
        genres: (a.genres ?? []).map(g => g.name),
        format: a.media_type ?? null,
        studio: mainStudio,
        _viewOnly: false,
      });
    });

    url = json.paging?.next ?? null;
    if (url) await sleep(150);
  }

  mergeExternalItems(items);
  showToast(`MAL: ${items.length} anime loaded`);
  // Build origMap so syncToMAL can diff against current state
  const origMap = new Map();
  items.forEach(a => origMap.set(a.malId, { status: a.status, score: a.score, epCur: a.epCur }));
  window._malOrigMap = origMap;
  window._malItems = items;
}

function detectType(content, filename) {
  const ext = filename.split('.').pop().toLowerCase();
  if (ext === 'xml') return 'wl-xml';
  if (ext === 'json' || ext === '') {
    try {
      const p = JSON.parse(content);
      if (p.meta?.exportedAt && Array.isArray(p.anime)) return 'cw';
      if (p.meta?.site || p.meta?.scrapedAt) {
        if (p.watching !== undefined || p.finished !== undefined) return 'cw';
      }
      const allItems = [...(p.watching||[]), ...(p.finished||[])];
      if (allItems.length && allItems[0]?.rank !== undefined) return 'cw';
      const WL_KEYS = ['Watching','Completed','On-Hold','Dropped','Plan to Watch','watching','completed','on_hold','dropped','plan_to_watch'];
      if (WL_KEYS.some(k => Array.isArray(p[k]))) return 'wl-json';
      if (Array.isArray(p) && p[0]?.status) return 'wl-json';
      if (Array.isArray(p.data)) return 'wl-json';
      if (p.watching !== undefined || p.finished !== undefined) return 'cw';
    } catch {}
  }
  return 'unknown';
}

function typeLabel(t) { return {cw:'CW Export', 'wl-json':'Watchlist (JSON)', 'wl-xml':'Watchlist (XML)', unknown:'Unknown'}[t] ?? t; }
function typeIcon(t)  { return {cw:'📺', 'wl-json':'📋', 'wl-xml':'📋', unknown:'❓'}[t] ?? '📄'; }

function assignPrefixes() {
  let pi = 0;
  loadedFiles.forEach(f => {
    if (f.type === 'cw') { f.prefix = PREFIXES[pi % PREFIXES.length]; pi++; }
    else f.prefix = null;
  });
}

function dzOver(e) { e.preventDefault(); document.getElementById('dz-main').classList.add('over'); }
function dzOut()   { document.getElementById('dz-main').classList.remove('over'); }
function dzDrop(e) { e.preventDefault(); dzOut(); handleFiles(e.dataTransfer.files); }
function dzFile(e) { handleFiles(e.target.files); e.target.value=''; }

function handleFiles(files) {
  [...files].forEach(file => {
    const r = new FileReader();
    r.onload = ev => {
      const content = ev.target.result;
      const type = detectType(content, file.name);
      let data;
      try {
        if (type === 'wl-xml') data = new DOMParser().parseFromString(content, 'text/xml');
        else data = JSON.parse(content);
      } catch { data = content; }
      loadedFiles.push({ name: file.name, type, data, prefix: null });
      assignPrefixes();
      renderFileList();
      document.getElementById('go-btn').disabled = loadedFiles.filter(f => f.type !== 'unknown').length === 0;
    };
    r.readAsText(file);
  });
}

function removeFile(i) {
  loadedFiles.splice(i, 1);
  assignPrefixes();
  renderFileList();
  document.getElementById('go-btn').disabled = loadedFiles.filter(f => f.type !== 'unknown').length === 0;
}

function renderFileList() {
  const fl = document.getElementById('file-list');
  if (!loadedFiles.length) { fl.style.display = 'none'; return; }
  fl.style.display = 'flex';
  fl.innerHTML = loadedFiles.map((f, i) => `
    <div class="file-item">
      <span class="fi-icon">${typeIcon(f.type)}</span>
      <div class="fi-info">
        <div class="fi-name">${x(f.name)}</div>
        <div class="fi-type">${typeLabel(f.type)}${f.type === 'unknown' ? ' — will be skipped' : ''}</div>
      </div>
      ${f.prefix ? `<span class="fi-prefix">${f.prefix}</span>` : ''}
      <button class="fi-remove" onclick="removeFile(${i})" title="Remove">✕</button>
    </div>`).join('');
}

// ══════════════════════════════════════════════
//  PARSERS & MERGE LOGIC
// ══════════════════════════════════════════════
function parseCw(data, prefix) {
  let items = Array.isArray(data.anime) ? data.anime : [...(data.watching||[]),...(data.finished||[])];
  return items.map(a => ({
    _id:       (prefix||'') + (a._id??a.movieId??a.slug??a.title),
    slug:      a.slug??null, episodeId:a.episodeId??null,
    malId:     a.malId??null, anilistId:a.anilistId??null,
    title:     a.title??null, titleJp:a.titleJp??null,
    thumb:     a.thumb??a.thumbnail??null, banner: a.banner??null, url: a.url??null,
    epCur:     a.epCur??a.episodes?.current??null, epTot: a.epTot??a.episodes?.total??null,
    epSub:     a.epSub??a.episodes?.sub??null, epDub: a.epDub??a.episodes?.dub??null,
    epWatched: a.epWatched??a.episodes?.watched??null,
    timeCur:   a.timeCur??a.time?.current??null, timeTot: a.timeTot??a.time?.total??null,
    timeCurSec:a.timeCurSec??a.time?.currentSec??0, timeTotSec: a.timeTotSec??a.time?.totalSec??0,
    prog:      a.prog??a.time?.progressPct??null,
    status:    a.status??null, score: a.score??null,
    startDate: a.startDate??null, finishDate:a.finishDate??null, rewatching:a.rewatching??false,
    rank:      a.rank??null, rankLabel: prefix ? `${prefix}${a.rank??'?'}` : (a.rankLabel??null),
    prefix:    prefix??a.prefix??null, fromCw:true, fromWl:a.fromWl??false,
  }));
}

function normSt(s) {
  if (!s) return null;
  const r = s.toLowerCase().replace(/[-_ ]/g,'');
  if (r.includes('watch')&&!r.includes('plan')) return 'watching';
  if (r.includes('complet')||r.includes('finish')) return 'finished';
  if (r.includes('hold'))  return 'on_hold';
  if (r.includes('drop'))  return 'dropped';
  if (r.includes('plan'))  return 'plan_to_watch';
  return s;
}

function malIdFrom(u){ const m=String(u||'').match(/myanimelist\.net\/anime\/(\d+)/); return m?m[1]:null; }

function wlNorm(a, sk) {
  return { 
    _id:malIdFrom(a.link||a.url||a.malUrl)??a.title??a.name, slug:null, episodeId:null, 
    malId:malIdFrom(a.link||a.url||a.malUrl), anilistId:null,
    title:a.title??a.name??null, titleJp:a.titleJp??a.japanese_title??null,
    thumb:a.thumbnail??a.image??null, banner:null, url:a.url??a.link??null,
    epCur:a.my_watched_episodes??a.epWatched??null, epTot:a.episodes??a.total_episodes??null,
    epSub:null, epDub:null, epWatched:a.my_watched_episodes??a.epWatched??null,
    timeCur:null, timeTot:null, timeCurSec:0, timeTotSec:0, prog:null,
    status:normSt(sk||a.status||a.my_status), score:a.score??a.my_score??null,
    startDate:a.start_date??a.my_start_date??null, finishDate:a.finish_date??a.my_finish_date??null,
    rewatching:false, rank:null, rankLabel:null, prefix:null, fromCw:false, fromWl:true 
  };
}

function parseWlJson(wl) {
  if (Array.isArray(wl._flat)) return wl._flat; // external fetch bypass
  const out=[], KEYS=['watching','completed','on_hold','dropped','plan_to_watch', 'Watching','Completed','On-Hold','Dropped','Plan to Watch'];
  if (Array.isArray(wl)) wl.forEach(a=>out.push(wlNorm(a,null)));
  else { KEYS.forEach(k=>(wl[k]||[]).forEach(a=>out.push(wlNorm(a,k)))); (wl.data||[]).forEach(a=>out.push(wlNorm(a,null))); }
  return out;
}

function parseWlXml(xml) {
  const out=[];
  xml.querySelectorAll('anime').forEach(n=>{
    const g=t=>n.querySelector(t)?.textContent?.trim()??null;
    out.push({ _id:g('series_animedb_id')??g('series_title'), slug:null, episodeId:null,
      malId:g('series_animedb_id'), title:g('series_title'), titleJp:null, thumb:null, banner:null,
      url:g('series_animedb_id')?`https://myanimelist.net/anime/${g('series_animedb_id')}`:null,
      epCur:g('my_watched_episodes')?+g('my_watched_episodes'):null, epTot:g('series_episodes')?+g('series_episodes'):null,
      epSub:null, epDub:null, epWatched:g('my_watched_episodes')?+g('my_watched_episodes'):null,
      timeCur:null, timeTot:null, timeCurSec:0, timeTotSec:0, prog:null,
      status:normSt(g('my_status')), score:g('my_score')?+g('my_score'):null,
      startDate:g('my_start_date'), finishDate:g('my_finish_date'), rewatching:g('my_rewatching')==='1', 
      rank:null, rankLabel:null, prefix:null, fromCw:false, fromWl:true });
  });
  if (!out.length) {
    xml.querySelectorAll('item').forEach(n=>{
      const g=t=>n.querySelector(t)?.textContent?.trim()??null;
      out.push(wlNorm({title:g('n')||g('title'),link:g('link')||g('url')}, n.closest('folder')?.querySelector('n')?.textContent?.trim()??null));
    });
  }
  return out;
}

const PRIORITY = { finished: 5, dropped: 4, on_hold: 3, plan_to_watch: 2, watching: 1, null: 0 };
function prioOf(s) { return PRIORITY[s] ?? PRIORITY['null']; }
function bestStatus(a, b) { return prioOf(a) >= prioOf(b) ? a : b; }
function bestEpCur(a, b) {
  const na = a ?? 0, nb = b ?? 0;
  const winner = na >= nb ? a : b;
  return winner === 0 ? null : winner;
}

function buildMasterList(files) {
  const cwFiles = files.filter(f => f.type === 'cw');
  const wlFiles = files.filter(f => f.type === 'wl-json' || f.type === 'wl-xml');

  const cwMap = new Map();
  cwFiles.forEach(f => {
    const items = parseCw(f.data, f.prefix);
    items.forEach(a => {
      const key = (a.title||'').toLowerCase().trim();
      const existing = cwMap.get(key);
      if (!existing) { cwMap.set(key, a); return; }
      const aScore = (a.epCur??0) * 100000 + (a.timeCurSec??0);
      const eScore = (existing.epCur??0) * 100000 + (existing.timeCurSec??0);
      if (aScore > eScore) cwMap.set(key, a);
    });
  });

  const cwItems = [...cwMap.values()];
  const wlMap = new Map();

  wlFiles.forEach(f => {
    const items = f.type === 'wl-xml' ? parseWlXml(f.data) : parseWlJson(f.data);
    items.forEach(w => {
      const key = w.malId ?? (w.title||'').toLowerCase().trim();
      if (!wlMap.has(key)) { wlMap.set(key, w); return; }
      const existing = wlMap.get(key);
      wlMap.set(key, { ...existing,
        status: bestStatus(w.status, existing.status),
        epCur:  bestEpCur(w.epCur, existing.epCur),
        epWatched: bestEpCur(w.epWatched, existing.epWatched),
        score: w.score ?? existing.score,
      });
    });
  });

  const wlItems = [...wlMap.values()];
  const byMal = new Map(), byTitle = new Map();
  
  wlItems.forEach(w => {
    if (w.malId) byMal.set(w.malId, w);
    if (w.title) byTitle.set(w.title.toLowerCase().trim(), w);
  });

  const out = [];
  const used = new Set();

  cwItems.forEach(cw => {
    const wl = (cw.malId && byMal.get(cw.malId)) || (cw.title && byTitle.get(cw.title.toLowerCase().trim()));
    if (wl) {
      used.add(wl._id);
      out.push({ ...cw,
        malId: wl.malId ?? cw.malId, titleJp: cw.titleJp ?? wl.titleJp,
        thumb: cw.thumb ?? wl.thumb, epTot: cw.epTot ?? wl.epTot,
        epCur: bestEpCur(cw.epCur, wl.epCur), epWatched: bestEpCur(cw.epWatched, wl.epWatched),
        status: bestStatus(cw.status, wl.status), score: wl.score ?? cw.score,
        startDate: wl.startDate ?? cw.startDate, finishDate: wl.finishDate ?? cw.finishDate,
        rewatching: wl.rewatching || cw.rewatching, fromWl: true,
      });
    } else { out.push(cw); }
  });

  wlItems.filter(w => !used.has(w._id)).forEach(w => out.push(w));

  const prefixOrder = cwFiles.map(f => f.prefix).filter(Boolean);
  out.sort((a, b) => {
    if (!a.rank && !b.rank) return 0;
    if (!a.rank) return 1;
    if (!b.rank) return -1;
    if (prefixOrder.length > 1) {
      const rankDiff = (a.rank??9999) - (b.rank??9999);
      if (rankDiff !== 0) return rankDiff;
      return prefixOrder.indexOf(a.prefix) - prefixOrder.indexOf(b.prefix);
    }
    return (a.rank??9999) - (b.rank??9999);
  });

  return out;
}

// ══════════════════════════════════════════════
//  LOCAL CSV DB
// ══════════════════════════════════════════════
function normTitle(s) { return String(s||'').toLowerCase().replace(/[^\w\s]/g,'').replace(/\s+/g,' ').trim(); }

function parseCSV(text) {
  const rows=[], lines=text.split(/\r?\n/), headers=splitCSVLine(lines[0]);
  for (let i=1;i<lines.length;i++) {
    if (!lines[i].trim()) continue;
    const vals=splitCSVLine(lines[i]), row={};
    headers.forEach((h,j)=>row[h.trim()]=(vals[j]??'').trim());
    rows.push(row);
  }
  return rows;
}

function splitCSVLine(line) {
  const out=[];let cur='';let inQ=false;
  for(let i=0;i<line.length;i++){const c=line[i];if(c==='"'){inQ=!inQ;}else if(c===','&&!inQ){out.push(cur);cur='';}else cur+=c;}
  out.push(cur); return out;
}

async function loadDB() {
  try {
    const r = await fetch('./anime.csv');
    if (!r.ok) { console.warn('[cw-analyse] anime.csv not found'); return; }
    const rows = parseCSV(await r.text());
    rows.forEach(row => {
      const entry = {
        anilistId: String(row.anime_id||'').trim(),
        malId:     String(row.mal_id||'').trim().replace(/\.0$/,''),
        banner:    (row.cover_image_large||'').trim(),
        titleEn:   (row.english_title||'').trim() || null,
        titleRo:   (row.title||'').trim() || null,
        titleJp:   (row.japanese_title||row.native_title||'').trim() || null,
        title:     (row.user_preferred_title||row.title||'').trim() || null,
      };
      if (!entry.anilistId && !entry.malId) return;
      if (entry.anilistId) dbById.set(entry.anilistId, entry);
      if (entry.malId && entry.malId !== 'nan') dbByMalId.set(entry.malId, entry);
      ['title','english_title','user_preferred_title', 'japanese_title', 'native_title'].forEach(k => {
        const t = normTitle(row[k]);
        if (t) dbByTitle.set(t, entry);
      });
    });
    dbLoaded = true;
    const lbEn = document.getElementById('lb-en');
    if (lbEn) lbEn.disabled = false;
  } catch(e) { console.warn('[cw-analyse] anime.csv error:', e.message); }
}

function dbLookup(a) {
  if (a.anilistId && dbById.has(a.anilistId))   return dbById.get(a.anilistId);
  if (a.malId     && dbByMalId.has(a.malId))    return dbByMalId.get(a.malId);
  for (const t of [a.title, a.titleJp]) {
    const h = dbByTitle.get(normTitle(t));
    if (h) return h;
  }
  return null;
}

// ══════════════════════════════════════════════
//  BANNER PIPELINE
// ══════════════════════════════════════════════
async function fetchBanners() {
  if (isReadOnly) return;
  const bar=document.getElementById('fetch-bar'), fill=document.getElementById('fb-fill'),
        msg=document.getElementById('fetch-msg'),  pct=document.getElementById('fetch-pct');
  bar.style.display='flex';
  const setBar=(p,m)=>{fill.style.width=p+'%';pct.textContent=p+'%';msg.textContent=m;};

  setBar(0,'Looking up local database…');
  let hits=0;
  list.forEach(a=>{
    const h=dbLookup(a); if(!h) return;
    if(!a.anilistId&&h.anilistId) a.anilistId=h.anilistId;
    if(!a.malId&&h.malId)         a.malId=h.malId;
    if(!a.titleEn&&h.titleEn)     a.titleEn=h.titleEn;
    if(!a.banner&&h.banner){a.banner=h.banner;updateCardBanner(a);hits++;}
  });
  setBar(10,`CSV — ${hits} banners resolved`);
  await sleep(200);

  const WATCH_HOSTS=['hianime.to','aniwatchtv.to','aniwatch.to','hianimez.to'];
  const needSync=list.filter(a=>{
    if(a.banner) return false; if(!a.url) return false;
    try{return WATCH_HOSTS.some(h=>new URL(a.url).hostname.includes(h));}catch{return false;}
  });
  
  if (needSync.length) {
    let done=0;
    for(let i=0;i<needSync.length;i+=6){
      const chunk=needSync.slice(i,i+6);
      await Promise.all(chunk.map(async a=>{
        try{
          const r=await fetch(a.url,{credentials:'include'}); if(!r.ok) return;
          const html=await r.text();
          const m=html.match(/<script[^>]+id=["']syncData["'][^>]*>([\s\S]*?)<\/script>/i); if(!m) return;
          const sd=JSON.parse(m[1]);
          if(sd.mal_id)     a.malId=String(sd.mal_id);
          if(sd.anilist_id) a.anilistId=String(sd.anilist_id);
          const h=dbLookup(a);
          if(h?.banner&&!a.banner){a.banner=h.banner;updateCardBanner(a);}
        }catch(_){}
        done++;
        setBar(10+Math.round(done/needSync.length*25),`Watch page IDs… ${done}/${needSync.length}`);
      }));
      if(i+6<needSync.length) await sleep(120);
    }
  }

  list.filter(a=>!a.banner&&a.malId).forEach(a=>{
    const h=dbByMalId.get(String(a.malId));
    if(h?.banner){a.banner=h.banner;updateCardBanner(a);}
  });
  setBar(38,'MAL ID lookup done'); await sleep(80);

  const needApi=list.filter(a=>!a.banner);
  if (needApi.length) {
    let done=0;
    for(let i=0;i<needApi.length;i+=50){
      const chunk=needApi.slice(i,i+50);
      try{
        const fields=chunk.map((a,idx)=>{
          if(a.anilistId) return `a${idx}: Media(id:${a.anilistId},type:ANIME){id idMal coverImage{extraLarge large}}`;
          const q=(a.title||'').replace(/"/g,'\\"');
          return `a${idx}: Media(search:"${q}",type:ANIME){id idMal coverImage{extraLarge large}}`;
        }).join('\n');
        const r=await fetch('https://graphql.anilist.co/',{method:'POST',
          headers:{'Content-Type':'application/json','Accept':'application/json'},
          body:JSON.stringify({query:`query{${fields}}`})});
        if(r.ok){
          const{data}=await r.json();
          chunk.forEach((a,idx)=>{
            const node=data?.[`a${idx}`]; if(!node) return;
            if(!a.anilistId&&node.id)    a.anilistId=String(node.id);
            if(!a.malId&&node.idMal)     a.malId=String(node.idMal);
            const img=node.coverImage?.extraLarge??node.coverImage?.large??null;
            if(img&&!a.banner){a.banner=img;updateCardBanner(a);}
          });
        }
      }catch(_){}
      done+=chunk.length;
      setBar(40+Math.round(done/needApi.length*35),`AniList API… ${done}/${needApi.length}`);
      if(i+50<needApi.length) await sleep(250);
    }
  }

  const needJikan=list.filter(a=>!a.banner);
  if (needJikan.length) {
    let done=0;
    for(const a of needJikan){
      try{
        let jid=a.malId;
        if(!jid&&a.title){
          const sq=await jFetch(`https://api.jikan.moe/v4/anime?q=${encodeURIComponent(a.title)}&limit=1`);
          jid=sq?.data?.[0]?.mal_id?String(sq.data[0].mal_id):null;
          if(jid) a.malId=jid;
        }
        if(jid){
          const pics=await jFetch(`https://api.jikan.moe/v4/anime/${jid}/pictures`);
          const img=pics?.data?.at(-1)?.jpg?.large_image_url??pics?.data?.[0]?.jpg?.large_image_url??null;
          if(img){a.banner=img;updateCardBanner(a);}
        }
      }catch(_){}
      done++;
      setBar(76+Math.round(done/needJikan.length*18),`Jikan… ${done}/${needJikan.length}`);
      await sleep(380);
    }
  }

  list.filter(a=>!a.banner&&a.thumb).forEach(a=>{a.banner=a.thumb;updateCardBanner(a);});
  setBar(100,`Done`);
  await sleep(1200);
  bar.style.display='none';
}

function updateCardBanner(a) {
  const card=document.querySelector(`.card[data-id="${CSS.escape(String(a._id))}"]`);
  if(!card) return;
  let img=card.querySelector('.c-banner img');
  if(!img){img=document.createElement('img');img.loading='lazy';card.querySelector('.c-banner').prepend(img);}
  img.src=a.banner; img.style.display='';
  const ph=card.querySelector('.c-banner .ph'); if(ph) ph.style.display='none';
  const si=document.getElementById('sheet-banner-'+sid(a._id));
  if(si) si.src=a.banner;
}

async function jFetch(url,retries=2){
  for(let i=0;i<=retries;i++){
    const r=await fetch(url);
    if(r.status===429){await sleep(1400);continue;}
    if(!r.ok) return null;
    return r.json();
  }
  return null;
}
function sleep(ms){return new Promise(r=>setTimeout(r,ms));}

// ══════════════════════════════════════════════
//  UI BUILDING
// ══════════════════════════════════════════════
async function buildDashboard(sharedList) {
  if (sharedList) { list = sharedList; isReadOnly = true; } 
  else { list = buildMasterList(loadedFiles.filter(f => f.type !== 'unknown')); }

  document.getElementById('import-screen').style.display='none';
  document.getElementById('dashboard').style.display='block';
  
  if (isReadOnly) {
    document.getElementById('share-banner').style.display='block';
    document.getElementById('tb-back').style.display='none';
    document.getElementById('xbar').innerHTML=`<button class="xbtn" onclick="exportJSON()">JSON</button>`;
  }

  updateStats(); 
  rerender();
  await dbReady;
  fetchBanners();
}

function updateStats() {
  document.getElementById('s-total').textContent=list.length;
  document.getElementById('s-watch').textContent=list.filter(a=>a.status==='watching').length;
  document.getElementById('s-fin').textContent  =list.filter(a=>a.status==='finished').length;
  document.getElementById('s-hold').textContent =list.filter(a=>a.status==='on_hold').length;
  document.getElementById('s-drop').textContent =list.filter(a=>a.status==='dropped').length;
  document.getElementById('s-plan').textContent =list.filter(a=>a.status==='plan_to_watch').length;
  document.getElementById('s-inc').textContent  =list.filter(a=>!a.status).length;
}

function displayTitle(a) {
  if (titleLang === 'en' && a.titleEn) return a.titleEn;
  if (titleLang === 'jp' && a.titleJp) return a.titleJp;
  return a.title ?? '';
}

function setLang(lang, btn) {
  titleLang = lang;
  document.querySelectorAll('.lang-switch .lb').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  rerender();
}

function toggleStatsDropdown() {
  const dd = document.getElementById('stats-dropdown');
  dd.classList.toggle('open');
  if (dd.classList.contains('open')) {
    setTimeout(() => {
      const handler = e => {
        if (!dd.contains(e.target) && !e.target.closest('.stats-toggle')) {
          dd.classList.remove('open');
          document.removeEventListener('click', handler);
        }
      };
      document.addEventListener('click', handler);
    }, 0);
  }
}

// ══════════════════════════════════════════════
//  UNIFIED SEARCH & RENDER
// ══════════════════════════════════════════════
function rerender() {
  const q = document.getElementById('tb-search').value.toLowerCase().trim();
  const s = document.getElementById('sort-sel').value;

  // 1. MAIN GRID (Items in List)
  let vis = [...list];
  if(activeFilter === 'watching') vis = vis.filter(a=>a.status==='watching');
  if(activeFilter === 'finished') vis = vis.filter(a=>a.status==='finished');
  if(activeFilter === 'plan_to_watch') vis = vis.filter(a=>a.status==='plan_to_watch');
  
  if(q) vis = vis.filter(a => [a.title, a.titleJp, a.titleEn].some(t => (t||'').toLowerCase().includes(q)));
  
  if(s==='title')    vis.sort((a,b)=>(a.title||'').localeCompare(b.title||''));
  if(s==='score')    vis.sort((a,b)=>(b.score??-1)-(a.score??-1));
  if(s==='progress') vis.sort((a,b)=>(b.prog??0)-(a.prog??0));

  document.getElementById('res-info').textContent=`Showing ${vis.length} of ${list.length}`;
  const grid = document.getElementById('grid');
  grid.innerHTML='';
  
  if(!vis.length){grid.innerHTML='<div class="empty"><div class="big">¯\\_(ツ)_/¯</div><div>Nothing here</div></div>';}
  else vis.forEach((a,i) => grid.appendChild(makeCard(a,i)));

  // 2. NOT IN LIST GRID (from staging or unified search query)
  let ns = document.getElementById('nil-section');
  if (!ns) {
    ns = document.createElement('div');
    ns.id = 'nil-section';
    ns.className = 'nil-section';
    document.querySelector('.grid-wrap').appendChild(ns);
  }

  // If there's no query, only show the section if we have staged items and are on "All"
  if (!q && (!notInList.length || activeFilter !== 'all')) {
    ns.style.display = 'none';
    return;
  }
  ns.style.display = 'block';

  ns.innerHTML = `
    <div class="nil-hdr">
      <div class="nil-label">NOT IN LIST</div>
      ${notInList.length ? `<div class="nil-count">${notInList.length} staged</div>` : ''}
      <div class="nil-rule"></div>
    </div>
    <div class="anime-grid" id="nil-grid"></div>
  `;

  const nilGrid = ns.querySelector('#nil-grid');
  let renderedNilCount = 0;

  // Render matching items that are already "staged" (notInList)
  const visNil = notInList.filter(a => !q || [a.title,a.titleJp,a.titleEn].some(t=>(t||'').toLowerCase().includes(q)));
  visNil.forEach((a,i) => {
    nilGrid.appendChild(makeCard(a, i, true));
    renderedNilCount++;
  });

  // If there's a search query, look through the anime.csv and show the hits
  if (q && dbLoaded) {
    const ql = q.replace(/[^\w\s]/g,'').replace(/\s+/g,' ').trim();
    const seen = new Set(visNil.map(a => a.anilistId || a.malId));
    let dbResultsFound = 0;

    for (const [t, entry] of dbByTitle) {
      if (t.includes(ql)) {
        const id = entry.anilistId || entry.malId;
        if (seen.has(id)) continue; 
        
        // Skip if already in the main user list
        if (list.some(a => (entry.anilistId && a.anilistId === entry.anilistId) || (entry.malId && a.malId === entry.malId))) continue;

        seen.add(id);
        dbResultsFound++;

        const preview = {
          _id: 'db_' + id, anilistId: entry.anilistId || null, malId: entry.malId || null,
          title: entry.titleRo || entry.titleEn || entry.title || '',
          titleJp: entry.titleJp || null, titleEn: entry.titleEn || null, titleRo: entry.titleRo || null,
          thumb: entry.banner || null, banner: entry.banner || null,
          epTot:null, epCur:null, epSub:null, epDub:null, epWatched:null,
          timeCur:null,timeTot:null,timeCurSec:0,timeTotSec:0,prog:null,
          status:null, score:null, startDate:null, finishDate:null, rewatching:false,
          rank:null, rankLabel:null, prefix:null, fromCw:false, fromWl:false,
          genres:[], format:null, studio:null, _isPreview:true,
        };
        
        nilGrid.appendChild(makeCard(preview, renderedNilCount++, true));
        if (dbResultsFound >= 24) break; 
      }
    }

    if (dbResultsFound === 0 && visNil.length === 0) {
      nilGrid.innerHTML = '<div class="nil-spinner" style="text-align:left;padding-left:10px;">No external matches found.</div>';
    }
  }
}

function isMobile(){return window.innerWidth<=640;}

function makeCard(a,i,isNil=false) {
  const el=document.createElement('div');
  el.className='card' + (isNil?' nil-card':'');
  el.dataset.id=String(a._id);
  // Simple fade-in, no stagger delay
  el.style.animation = 'fadeUp .15s ease both';
  
  if(isMobile()&&!isNil) el.onclick=()=>openSheet(a);
  if(isNil&&a._isPreview) el.onclick=()=>stageFromPreview(a);

  const prog=a.prog??(a.timeTotSec>0?Math.round(a.timeCurSec/a.timeTotSec*100):0);
  const stLabel={watching:'Watching',finished:'Finished',on_hold:'On Hold',dropped:'Dropped',plan_to_watch:'Plan to Watch'}[a.status]??'Unknown';
  const stCls=a.status??'unknown';
  const img=a.banner??a.thumb??null;
  const eid=sid(a._id);
  const ro=isReadOnly;

  el.innerHTML=`
    <div class="c-banner">
      ${img?`<img src="${x(img)}" loading="lazy" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">`:``}
      <div class="ph" style="${img?'display:none':''}">🎌</div>
      ${a.rankLabel?`<div class="c-rank">${a.rankLabel}</div>`:a.rank?`<div class="c-rank">#${a.rank}</div>`:''}
      <div class="c-status ${stCls}">${stLabel}</div>
      <div class="c-src">${a.fromCw?'<span class="cw">CW</span>':''}${a.fromWl?'<span class="wl">WL</span>':''}</div>
    </div>
    <div class="c-body">
      <div>
        <input class="c-title bebas" type="text" value="${x(displayTitle(a))}" placeholder="Title…"
          ${ro?'readonly':''} onchange="${ro?'':'sf(this,\''+eid+'\',\'title\')'}">
        ${a.titleJp&&titleLang!=='jp'?`<div class="c-titlejp">${x(a.titleJp)}</div>`:
          a.titleEn&&titleLang!=='en'?`<div class="c-titlejp">${x(a.titleEn)}</div>`:''}
      </div>
      <div class="stat-row">
        <div class="stat-pill"><span class="pl">Sub</span><span class="pv ${a.epSub==null?'null':''}">${a.epSub??'—'}</span></div>
        <div class="stat-pill"><span class="pl">Dub</span><span class="pv ${a.epDub==null?'null':''}">${a.epDub??'—'}</span></div>
        <div class="stat-pill"><span class="pl">Total</span><span class="pv ${a.epTot==null?'null':''}">${a.epTot??'—'}</span></div>
      </div>
      <div class="stat-row">
        <div class="ep-chip">
          <span class="pl">Ep</span>
          <input type="number" value="${a.epCur??''}" placeholder="?" ${ro?'readonly':''}
            onchange="${ro?'':'sf(this,\''+eid+'\',\'epCur\',true)'}">
          ${a.epTot!=null?`<span class="sep">/ ${a.epTot}</span>`:''}
        </div>
      </div>
      ${a.timeTotSec>0||a.timeCurSec>0?`
      <div class="time-section">
        <div class="time-hdr">
          <input class="time-cur" id="tc-${eid}" type="text" value="${a.timeCur??''}" placeholder="00:00"
            ${ro?'readonly':''} onchange="${ro?'':'setTC(\''+eid+'\',this.value)'}">
          <span class="time-pct" id="tp-${eid}">${prog}%</span>
          <span class="time-tot">${a.timeTot??''}</span>
        </div>
        <input type="range" class="scrubber" id="sc-${eid}"
          min="0" max="${a.timeTotSec||100}" value="${a.timeCurSec||0}"
          style="--p:${prog}%" ${ro?'disabled':''}
          oninput="${ro?'':'scrub(\''+eid+'\',this)'}">
      </div>`:''}
      <div class="score-row">
        <div class="score-lbl">Score</div>
        <div class="stars" id="st-${eid}">
          ${[1,2,3,4,5,6,7,8,9,10].map(n=>`<span class="star ${ro?'ro':''} ${(a.score??0)>=n?'on':''}"
            ${ro?'':'onclick="setScore(\''+eid+'\','+n+')"'} title="${n}/10">★</span>`).join('')}
        </div>
        <input type="number" class="score-num" id="si-${eid}" min="0" max="10"
          value="${a.score??''}" placeholder="—" ${ro?'readonly':''}
          onchange="${ro?'':'setScore(\''+eid+'\',this.value===\'\'?null:+this.value)'}">
      </div>
      <div class="status-row">
        <div class="status-lbl">Status</div>
        <select class="status-sel" ${ro?'disabled':''} onchange="${ro?'':isNil?`sfNilStatus(this,'${eid}')`:(`sf(this,'${eid}','status');updateStats();rerender()`)}">
          <option value="" ${!a.status?'selected':''}>Unknown</option>
          <option value="watching" ${a.status==='watching'?'selected':''}>Watching</option>
          <option value="finished" ${a.status==='finished'?'selected':''}>Completed</option>
          <option value="on_hold" ${a.status==='on_hold'?'selected':''}>On Hold</option>
          <option value="dropped" ${a.status==='dropped'?'selected':''}>Dropped</option>
          <option value="plan_to_watch" ${a.status==='plan_to_watch'?'selected':''}>Plan to Watch</option>
        </select>
      </div>
      <div class="mal-row-card">
        <div class="mal-lbl">MAL</div>
        ${a.malId
          ?`<a class="mal-link" href="https://myanimelist.net/anime/${a.malId}" target="_blank">#${a.malId}</a>`
          :`<input class="mal-id-inp" type="text" placeholder="Not linked…" ${ro?'readonly':''}
              onchange="${ro?'':'sf(this,\''+eid+'\',\'malId\',false,true)'}">
            <div class="ndot" title="No MAL ID"></div>`}
      </div>
    </div>`;
  return el;
}

// ══════════════════════════════════════════════
//  INTERACTIONS
// ══════════════════════════════════════════════
function openSheet(a) {
  const prog=a.prog??(a.timeTotSec>0?Math.round(a.timeCurSec/a.timeTotSec*100):0);
  const stLabel={watching:'Watching',finished:'Finished',on_hold:'On Hold',dropped:'Dropped',plan_to_watch:'Plan to Watch'}[a.status]??'Unknown';
  const img=a.banner??a.thumb??null;
  const eid=sid(a._id);

  document.getElementById('sheet-content').innerHTML=`
    ${img?`<img id="sheet-banner-${eid}" class="sheet-banner" src="${x(img)}" alt="">`:
          `<div style="height:60px"></div>`}
    <div class="sheet-body">
      <div class="sheet-title">${x(a.title??'')}</div>
      ${a.titleJp?`<div class="sheet-jp">${x(a.titleJp)}</div>`:'<div style="margin-bottom:14px"></div>'}
      <div class="stat-row" style="margin-bottom:10px">
        <div class="stat-pill"><span class="pl">Sub</span><span class="pv">${a.epSub??'—'}</span></div>
        <div class="stat-pill"><span class="pl">Dub</span><span class="pv">${a.epDub??'—'}</span></div>
        <div class="stat-pill"><span class="pl">Total</span><span class="pv">${a.epTot??'—'}</span></div>
        <div class="stat-pill"><span class="pl">Status</span><span class="pv">${stLabel}</span></div>
      </div>
      ${a.timeTotSec>0?`
      <div class="time-section" style="margin-bottom:12px">
        <div class="time-hdr">
          <span class="time-cur">${a.timeCur??'—'}</span>
          <span class="time-pct">${prog}%</span>
          <span class="time-tot">${a.timeTot??''}</span>
        </div>
        <input type="range" class="scrubber" min="0" max="${a.timeTotSec}" value="${a.timeCurSec}" style="--p:${prog}%" disabled>
      </div>`:''}
      <div class="score-row" style="margin-bottom:10px">
        <div class="score-lbl">Score</div>
        <div class="stars">
          ${[1,2,3,4,5,6,7,8,9,10].map(n=>`<span class="star ro ${(a.score??0)>=n?'on':''}">★</span>`).join('')}
        </div>
        <span style="font-size:.78rem;color:var(--text2);margin-left:4px">${a.score??'—'}/10</span>
      </div>
      ${a.malId?`<div style="font-size:.74rem;color:var(--text3)">MAL: <a class="mal-link" href="https://myanimelist.net/anime/${a.malId}" target="_blank">#${a.malId}</a></div>`:''}
    </div>`;

  document.getElementById('sheet-overlay').style.display='block';
  document.getElementById('sheet').classList.add('open');
}

function closeSheet() {
  document.getElementById('sheet').classList.remove('open');
  document.getElementById('sheet-overlay').style.display='none';
}

function byEid(eid){ return list.find(a=>sid(a._id)===eid) || notInList.find(a=>sid(a._id)===eid); }
function sf(el,eid,field,isNum=false,nullIfEmpty=false){
  const a=byEid(eid); if(!a) return;
  let v=el.value;
  if(isNum) v=v===''?null:+v;
  if(nullIfEmpty) v=v.trim()===''?null:v.trim();
  a[field]=v;
}

function sfNilStatus(el, eid) {
  const a = notInList.find(a => sid(a._id) === eid);
  if (!a) return;
  a.status = el.value || null;
  if (a.status) {
    pendingPromote = a._id;
    const card = document.querySelector(`#nil-grid .card[data-id="${CSS.escape(String(a._id))}"]`);
    if (card) card.classList.add('card-pending');
  }
}

function stageFromPreview(a) {
  if (notInList.some(n => n._id === a._id)) return;
  const staged = { ...a, _isPreview: false };
  notInList.push(staged);
  rerender(); // re-runs unified search rendering
  showToast(`Staged: ${a.title ?? ''} — set a status to add to list`);
}

async function promoteCard(id) {
  const item = notInList.find(a => a._id === id);
  if (!item || !item.status) return;

  const nilCard = document.querySelector(`#nil-grid .card[data-id="${CSS.escape(String(id))}"]`);
  if (!nilCard) { _doInstantPromote(id); return; }

  const fromRect = nilCard.getBoundingClientRect();
  notInList = notInList.filter(a => a._id !== id);
  list.unshift(item);
  updateStats();

  const clone = nilCard.cloneNode(true);
  clone.style.cssText = `position:fixed;left:${fromRect.left}px;top:${fromRect.top}px;width:${fromRect.width}px;height:${fromRect.height}px;z-index:9999;pointer-events:none;will-change:transform,opacity;border-radius:var(--r);overflow:hidden;border:1px solid var(--accent);`;
  document.body.appendChild(clone);

  const mainGrid = document.getElementById('grid');
  const oldPos = {};
  mainGrid.querySelectorAll('.card').forEach(c => {
    oldPos[c.dataset.id] = { top: c.getBoundingClientRect().top, left: c.getBoundingClientRect().left };
  });

  rerender();

  const vpH = window.innerHeight;
  mainGrid.querySelectorAll('.card').forEach(c => {
    const cid = c.dataset.id;
    if (cid === String(id)) return;
    const old = oldPos[cid]; if (!old) return;
    const now = c.getBoundingClientRect();
    const dx = old.left - now.left, dy = old.top - now.top;
    if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5) return;
    if (old.top > vpH + 300 && now.top > vpH + 300) return;
    c.animate([{ transform:`translate(${dx}px,${dy}px)` }, { transform:'translate(0,0)' }],
      { duration:380, easing:'cubic-bezier(.25,.46,.45,.94)', fill:'forwards' });
  });

  const newCard = mainGrid.querySelector(`.card[data-id="${CSS.escape(String(id))}"]`);
  if (newCard) newCard.style.opacity = '0';
  const toRect = newCard ? newCard.getBoundingClientRect() : { left: fromRect.left, top: 80 };

  const dx = toRect.left - fromRect.left, dy = toRect.top  - fromRect.top;
  const dist = Math.sqrt(dx*dx + dy*dy);
  const dur = Math.min(680, Math.max(420, dist * 0.55));
  const ox = dx * 0.07, oy = dy * 0.09;

  const anim = clone.animate([
    { transform:'translate(0,0) scale(1) rotate(0deg)', opacity:1, offset:0 },
    { transform:`translate(${dx*.38}px,${dy*.32}px) scale(.93) rotate(-1.8deg)`, opacity:1, offset:.28 },
    { transform:`translate(${dx+ox}px,${dy+oy}px) scale(.96) rotate(.6deg)`, opacity:1, offset:.68 },
    { transform:`translate(${dx-ox*.5}px,${dy-oy*.5}px) scale(1.03) rotate(-.3deg)`, opacity:.75, offset:.84 },
    { transform:`translate(${dx}px,${dy}px) scale(1) rotate(0deg)`, opacity:0, offset:1 },
  ], { duration:dur, easing:'linear', fill:'forwards' });

  anim.onfinish = () => {
    clone.remove();
    if (newCard) {
      newCard.style.opacity = '';
      newCard.classList.add('card-landing');
      setTimeout(() => newCard.classList.remove('card-landing'), 520);
    }
  };
}

function _doInstantPromote(id) {
  const item = notInList.find(a => a._id === id);
  if (!item) return;
  notInList = notInList.filter(a => a._id !== id);
  list.unshift(item);
  updateStats();
  rerender();
}

document.addEventListener('click', e => {
  if (!pendingPromote) return;
  const dash = document.getElementById('dashboard');
  if (!dash || !dash.contains(e.target)) return; 
  const pendCard = document.querySelector(`.card[data-id="${CSS.escape(String(pendingPromote))}"]`);
  if (pendCard && pendCard.contains(e.target)) return;
  if (e.target.closest('#nil-grid .card')) return;
  const id = pendingPromote;
  pendingPromote = null;
  promoteCard(id);
}, true);

function scrub(eid,el){
  const a=byEid(eid); if(!a) return;
  const sec=+el.value; a.timeCurSec=sec; a.timeCur=s2t(sec);
  if(a.timeTotSec>0){a.prog=Math.round(sec/a.timeTotSec*100);el.style.setProperty('--p',a.prog+'%');}
  const tc=document.getElementById('tc-'+eid); if(tc) tc.value=a.timeCur;
  const tp=document.getElementById('tp-'+eid); if(tp) tp.textContent=(a.prog??0)+'%';
}
function setTC(eid,val){
  const a=byEid(eid); if(!a) return;
  a.timeCur=val; a.timeCurSec=t2s(val);
  const sc=document.getElementById('sc-'+eid);
  if(sc){sc.value=a.timeCurSec;if(a.timeTotSec>0){const p=Math.round(a.timeCurSec/a.timeTotSec*100);a.prog=p;sc.style.setProperty('--p',p+'%');}}
  const tp=document.getElementById('tp-'+eid); if(tp&&a.prog!=null) tp.textContent=a.prog+'%';
}
function setScore(eid,n){
  const a=byEid(eid); if(!a) return;
  a.score=(a.score===n)?null:n;
  const inp=document.getElementById('si-'+eid); if(inp) inp.value=a.score??'';
  document.querySelectorAll(`#st-${eid} .star`).forEach((s,i)=>s.classList.toggle('on',i<(a.score??0)));
}

function setFilter(f,btn){
  activeFilter=f;
  document.querySelectorAll('.tb-filters .fb').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on'); rerender();
}

// ══════════════════════════════════════════════
//  ACCOUNTS & OAUTH
// ══════════════════════════════════════════════
function setConnected(acct) {
  connectedAccount = acct;
  const sync = document.getElementById('tb-sync');
  if (acct) {
    if (sync) sync.style.display = acct.viewOnly ? 'none' : 'inline-block';
  } else {
    if (sync) sync.style.display = 'none';
  }
}

function connectAniList() {
  window.location.href = `https://anilist.co/api/v2/oauth/authorize?client_id=${AL_CLIENT_ID}&response_type=token`;
}

function connectAniListImport() {
  connectAniList();
}

function connectMAL() { showToast('Use the Connect button in the import screen'); }

function alScore(s) {
  if (!s || s === 0) return null;
  // AniList scores are always 0–100. Convert to 1–10 scale.
  const score = Math.round(s / 10);
  return score < 1 ? null : Math.min(10, score);
}
function alStatus(s){
  return {CURRENT:'watching',COMPLETED:'finished',PAUSED:'on_hold',
          DROPPED:'dropped',PLANNING:'plan_to_watch',REPEATING:'watching'}[s] ?? null;
}
function malStatus(s){
  return {watching:'watching',completed:'finished',on_hold:'on_hold',
          dropped:'dropped',plan_to_watch:'plan_to_watch'}[s] ?? normSt(s);
}
function toAlStatus(s){
  return {watching:'CURRENT',finished:'COMPLETED',on_hold:'PAUSED',
          dropped:'DROPPED',plan_to_watch:'PLANNING'}[s] ?? 'CURRENT';
}

async function fetchAniListByUser(username, viewOnly=false, token=null) {
  const btn = document.getElementById('al-connect-btn') ?? document.getElementById('al-analyse-btn');
  if (btn) { btn.textContent='…'; btn.disabled=true; }

  // Simplified query - gutted the custom list stuff
  const query = `query($name:String){
    MediaListCollection(userName:$name,type:ANIME){
      lists{ name status entries{ mediaId score status progress
          media{ idMal title{romaji english native userPreferred}
            coverImage{large extraLarge} episodes format genres tags{name rank}
            startDate{year} studios{nodes{name isAnimationStudio}} } } } } }`;

  try {
    const headers = {'Content-Type':'application/json','Accept':'application/json'};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const r = await fetch('https://graphql.anilist.co/',{method:'POST',headers,body:JSON.stringify({query,variables:{name:username}})});
    if (r.status === 401) {
      localStorage.removeItem('anilist_token');
      showToast('❌ Token expired — please reconnect');
      if (btn) { btn.textContent='Connect →'; btn.disabled=false; } return;
    }
    const {data,errors} = await r.json();
    if (errors) throw new Error(errors[0].message);
    const lists = data?.MediaListCollection?.lists ?? [];
    if (!lists.length) throw new Error('No anime found');

    const items = [];
    const origMap = new Map();
    lists.forEach(lst => {
      lst.entries.forEach(e => {
        const m = e.media;
        const mainStudio = m.studios?.nodes?.find(s=>s.isAnimationStudio)?.name ?? null;
        const topTags = (m.tags??[]).sort((a,b)=>b.rank-a.rank).slice(0,5).map(t=>t.name);
        const item = {
          _id:String(e.mediaId), slug:null, episodeId:null,
          malId:m.idMal?String(m.idMal):null, anilistId:String(e.mediaId),
          title:m.title.userPreferred??m.title.romaji??null, titleJp:m.title.native??null,
          titleEn:m.title.english??null, titleRo:m.title.romaji??null,
          thumb:m.coverImage?.large??null, banner:m.coverImage?.extraLarge??m.coverImage?.large??null, url:null,
          epCur:e.progress??null, epTot:m.episodes??null,
          epSub:null, epDub:null, epWatched:e.progress??null,
          timeCur:null,timeTot:null,timeCurSec:0,timeTotSec:0,prog:null,
          status:alStatus(e.status), score:alScore(e.score),
          startDate:m.startDate?.year?`${m.startDate.year}-01-01`:null, finishDate:null,
          rewatching:e.status==='REPEATING', rank:null, rankLabel:null, prefix:null,
          fromCw:false, fromWl:true,
          genres:m.genres??[], tags:topTags, format:m.format??null, studio:mainStudio,
          alStatus:e.status, _viewOnly:viewOnly,
        };
        items.push(item);
        origMap.set(item._id, {status:item.status,score:item.score,epCur:item.epCur});
      });
    });

    window._alOrigMap = origMap;
    window._alViewOnly = viewOnly;
    mergeExternalItems(items);
    showToast(`AniList: ${items.length} anime loaded`);
    window._alItems = items;
    if (!viewOnly && token) setConnected({type:'anilist',username,token,viewOnly:false});
  } catch(e) {
    showToast('❌ AniList: ' + e.message);
    throw e;
  } finally {
    const restoreBtn = document.getElementById('al-connect-btn') ?? document.getElementById('al-analyse-btn');
    if (restoreBtn) { restoreBtn.textContent = viewOnly ? 'Fetch (view-only)' : (restoreBtn.id === 'al-analyse-btn' ? 'Analyse list →' : 'Connect →'); restoreBtn.disabled=false; }
  }
}

// toggleMalInput / connectMAL / fetchMAL replaced by MAL OAuth2 flow above



function mergeExternalItems(items) {
  loadedFiles = loadedFiles.filter(f => !f._external);
  loadedFiles.push({name:`account (${items.length})`,type:'wl-json',data:{_flat:items},prefix:null,_external:true});
  assignPrefixes(); renderFileList();
}

async function syncToAccount() {
  if (!connectedAccount) { showToast('No account connected'); return; }
  if (connectedAccount.viewOnly) { showToast('View-only — cannot sync'); return; }
  if (!list.length) { showToast('Nothing to sync'); return; }
  if (connectedAccount.type === 'anilist') await syncToAniList();
  else if (connectedAccount.type === 'mal') await syncToMAL();
}

async function syncToAniList() {
  const token = connectedAccount?.token || localStorage.getItem('anilist_token');
  if (!token) { connectAniList(); return; }
  await doAniListSync(token);
}

async function doAniListSync(token) {
  const origMap = window._alOrigMap ?? new Map();
  const changed = list.filter(a => {
    if (!a.anilistId) return false;
    const orig = origMap.get(a._id);
    if (!orig) return true;
    return orig.status !== a.status || orig.score !== a.score || orig.epCur !== a.epCur;
  });
  if (!changed.length) { showToast('No changes to sync'); return; }

  const bar=document.getElementById('fetch-bar'),fill=document.getElementById('fb-fill'),
        msg=document.getElementById('fetch-msg'),pct=document.getElementById('fetch-pct');
  bar.style.display='flex';
  const setBar=(p,m)=>{fill.style.width=p+'%';pct.textContent=p+'%';msg.textContent=m;};
  setBar(0,`Syncing ${changed.length} changes…`);

  const mutation=`mutation($mediaId:Int,$status:MediaListStatus,$score:Float,$progress:Int){
    SaveMediaListEntry(mediaId:$mediaId,status:$status,score:$score,progress:$progress){id status score progress}}`;

  const BATCH=25, CONCURRENT=3, RETRY=2;
  let ok=0, fail=0; const failed=[];

  async function syncOne(a, attempt=0) {
    try {
      const r = await fetch('https://graphql.anilist.co/',{method:'POST',
        headers:{'Content-Type':'application/json','Authorization':`Bearer ${token}`},
        body:JSON.stringify({query:mutation,variables:{
          mediaId:parseInt(a.anilistId), status:toAlStatus(a.status),
          score:a.score?a.score*10:0, progress:a.epCur??0}})});
      if (r.status===401) { localStorage.removeItem('anilist_token'); throw new Error('TOKEN_EXPIRED'); }
      const json=await r.json();
      if (json.errors) throw new Error(json.errors[0].message);
      origMap.set(a._id,{status:a.status,score:a.score,epCur:a.epCur});
      ok++;
    } catch(e) {
      if (e.message==='TOKEN_EXPIRED') { showToast('❌ Token expired — reconnect'); bar.style.display='none'; return; }
      if (attempt<RETRY) { await sleep(600); return syncOne(a,attempt+1); }
      fail++; failed.push(a.title??a._id);
    }
  }

  for (let i=0;i<changed.length;i+=BATCH) {
    const batch=changed.slice(i,i+BATCH);
    for (let j=0;j<batch.length;j+=CONCURRENT) {
      await Promise.all(batch.slice(j,j+CONCURRENT).map(a=>syncOne(a)));
      await sleep(350);
    }
    setBar(Math.round((i+batch.length)/changed.length*95),`Syncing… ${Math.min(i+BATCH,changed.length)}/${changed.length}`);
  }

  setBar(100,`Done — ${ok} synced${fail?`, ${fail} failed`:''}`);
  await sleep(1400); bar.style.display='none';
  if (fail) showToast(`⚠️ ${fail} failed: ${failed.slice(0,3).join(', ')}${failed.length>3?'…':''}`);
  else showToast(`✓ ${ok} changes synced`);
}

async function syncToMAL() {
  const token = connectedAccount?.token || localStorage.getItem('mal_token');
  if (!token) { connectMALImport(); return; }

  const origMap = window._malOrigMap ?? new Map();
  const changed = list.filter(a => {
    if (!a.malId) return false;
    const orig = origMap.get(a.malId);
    if (!orig) return true;
    return orig.status !== a.status || orig.score !== a.score || orig.epCur !== a.epCur;
  });
  if (!changed.length) { showToast('No changes to sync'); return; }

  const bar=document.getElementById('fetch-bar'),fill=document.getElementById('fb-fill'),
        msg=document.getElementById('fetch-msg'),pct=document.getElementById('fetch-pct');
  bar.style.display='flex';
  const setBar=(p,m)=>{fill.style.width=p+'%';pct.textContent=p+'%';msg.textContent=m;};
  setBar(0,`Syncing ${changed.length} MAL changes…`);

  let ok=0, fail=0; const failed=[];

  async function syncOne(a, attempt=0) {
    try {
      const body = new URLSearchParams();
      if (a.status) body.set('status', a.status === 'finished' ? 'completed' : a.status);
      if (a.score != null) body.set('score', String(a.score));
      if (a.epCur != null) body.set('num_watched_episodes', String(a.epCur));

      const r = await fetch(`https://api.myanimelist.net/v2/anime/${a.malId}/my_list_status`, {
        method: 'PATCH',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });
      if (r.status === 401) { localStorage.removeItem('mal_token'); throw new Error('TOKEN_EXPIRED'); }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      origMap.set(a.malId, { status: a.status, score: a.score, epCur: a.epCur });
      ok++;
    } catch(e) {
      if (e.message === 'TOKEN_EXPIRED') { showToast('❌ MAL token expired — reconnect'); bar.style.display='none'; return; }
      if (attempt < 2) { await sleep(600); return syncOne(a, attempt+1); }
      fail++; failed.push(a.title ?? a._id);
    }
  }

  const BATCH=10, CONCURRENT=2;
  for (let i=0;i<changed.length;i+=BATCH) {
    const batch=changed.slice(i,i+BATCH);
    for (let j=0;j<batch.length;j+=CONCURRENT) {
      await Promise.all(batch.slice(j,j+CONCURRENT).map(a=>syncOne(a)));
      await sleep(500); // MAL rate limit is stricter
    }
    setBar(Math.round((i+batch.length)/changed.length*95),`Syncing… ${Math.min(i+BATCH,changed.length)}/${changed.length}`);
  }
  window._malOrigMap = origMap;

  setBar(100,`Done — ${ok} synced${fail?`, ${fail} failed`:''}`);
  await sleep(1400); bar.style.display='none';
  if (fail) showToast(`⚠️ ${fail} failed: ${failed.slice(0,3).join(', ')}${failed.length>3?'…':''}`);
  else showToast(`✓ ${ok} MAL changes synced`);
}


async function shareList() {
  showToast('⏳ Uploading list…', 60000);
  try {
    const slim = list.map(a => ({
      _id:a._id, title:a.title, titleJp:a.titleJp,
      malId:a.malId, anilistId:a.anilistId,
      banner:a.banner, thumb:a.thumb,
      epCur:a.epCur, epTot:a.epTot, epSub:a.epSub, epDub:a.epDub, epWatched:a.epWatched,
      timeCur:a.timeCur, timeTot:a.timeTot, timeCurSec:a.timeCurSec, timeTotSec:a.timeTotSec, prog:a.prog,
      status:a.status, score:a.score, rank:a.rank, rankLabel:a.rankLabel,
      fromCw:a.fromCw, fromWl:a.fromWl,
    }));
    const r = await fetch(`${WORKER}/share`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cwa: true, list: slim }),
    });
    if (r.status === 413) throw new Error('List too large');
    if (r.status === 503) throw new Error('Storage unavailable — try again later');
    if (!r.ok) throw new Error(`Server error ${r.status}`);
    const { id } = await r.json();
    const url = `${location.href.split('#')[0]}#bin=${id}`;
    await navigator.clipboard.writeText(url);
    showToast('🔗 Link copied! Expires in 7 days.');
  } catch(e) { showToast('❌ Share failed: ' + e.message); }
}

async function checkShareUrl() {
  const hash = location.hash;
  if (!hash.startsWith('#bin=')) return;
  const id = hash.slice(5);
  if (!id) return;
  try {
    const r = await fetch(`${SHARE_WORKER_URL}/share/${id}`);
    if (r.status === 404) { alert('Share link has expired or is invalid.'); return; }
    if (!r.ok) throw new Error(`Server error ${r.status}`);
    const record = await r.json();
    if (!record?.cwa || !Array.isArray(record.list)) throw new Error('Invalid share data');
    buildDashboard(record.list);
  } catch(e) { alert('Could not load shared list: ' + e.message); }
}

function showToast(msg, ms=2400) {
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), ms);
}

function exportJSON(){ dl(JSON.stringify({meta:{exportedAt:new Date().toISOString(),total:list.length},anime:list},null,2),'cw-analyse.json','application/json'); }
function exportXML(){
  const rows=list.map(a=>`  <anime>
    <series_title>${xe(a.title)}</series_title>
    <series_animedb_id>${a.malId??''}</series_animedb_id>
    <series_episodes>${a.epTot??''}</series_episodes>
    <my_watched_episodes>${a.epCur??a.epWatched??''}</my_watched_episodes>
    <my_score>${a.score??0}</my_score>
    <my_status>${malSt(a.status)}</my_status>
    <my_start_date>${a.startDate??'0000-00-00'}</my_start_date>
    <my_finish_date>${a.finishDate??'0000-00-00'}</my_finish_date>
    <cw_rank>${a.rankLabel??a.rank??''}</cw_rank>
    <cw_current_ep>${a.epCur??''}</cw_current_ep>
    <cw_current_time>${a.timeCur??''}</cw_current_time>
    <cw_progress_pct>${a.prog??''}</cw_progress_pct>
  </anime>`).join('\n');
  dl(`<?xml version="1.0" encoding="UTF-8"?>\n<myanimelist>\n${rows}\n</myanimelist>`,'cw-analyse.xml','application/xml');
}
function exportMAL(){
  const rows=list.map(a=>`  <anime>
    <series_animedb_id>${a.malId??''}</series_animedb_id>
    <series_title>${xe(a.title)}</series_title>
    <series_episodes>${a.epTot??''}</series_episodes>
    <my_id>0</my_id>
    <my_watched_episodes>${a.epCur??a.epWatched??0}</my_watched_episodes>
    <my_start_date>${a.startDate??'0000-00-00'}</my_start_date>
    <my_finish_date>${a.finishDate??'0000-00-00'}</my_finish_date>
    <my_score>${a.score??0}</my_score>
    <my_status>${malSt(a.status)}</my_status>
    <my_rewatching>${a.rewatching?1:0}</my_rewatching>
    <my_rewatching_ep>0</my_rewatching_ep>
    <my_times_watched>0</my_times_watched>
    <my_priority>LOW</my_priority>
    <my_tags></my_tags>
    <my_discuss>1</my_discuss>
    <my_sns>default</my_sns>
    <update_on_import>1</update_on_import>
  </anime>`).join('\n');
  dl(`<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE MyAnimeList SYSTEM "http://myanimelist.net/static/dtd/2.1/myanimelist.dtd">\n<myanimelist>\n  <myinfo><user_export_type>1</user_export_type></myinfo>\n${rows}\n</myanimelist>`,'mal-import.xml','application/xml');
}
function malSt(s){return{finished:'Completed',on_hold:'On-Hold',dropped:'Dropped',plan_to_watch:'Plan to Watch'}[s]??'Watching';}

function goBack(){
  document.getElementById('dashboard').style.display='none';
  document.getElementById('import-screen').style.display='flex';
}

document.addEventListener('keydown', e => {
  const dash = document.getElementById('dashboard');
  if (!dash || dash.style.display === 'none') return;
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'SELECT') {
    e.preventDefault();
    document.getElementById('tb-search')?.focus();
  }
});

// ══════════════════════════════════════════════
//  STATS PAGE
// ══════════════════════════════════════════════
function openStatsPage() {
  renderStats();
  document.getElementById('stats-page').classList.add('open');
  document.getElementById('dashboard').style.display = 'none';
}
function closeStatsPage() {
  document.getElementById('stats-page').classList.remove('open');
  document.getElementById('dashboard').style.display = 'block';
}

function renderStats() {
  const body = document.getElementById('sp-body');
  const total     = list.length;
  const watching  = list.filter(a=>a.status==='watching').length;
  const finished  = list.filter(a=>a.status==='finished').length;
  const onHold    = list.filter(a=>a.status==='on_hold').length;
  const dropped   = list.filter(a=>a.status==='dropped').length;
  const planned   = list.filter(a=>a.status==='plan_to_watch').length;

  const totalEps  = list.reduce((s,a) => s + (a.epCur??0), 0);
  const totalSecs = list.reduce((s,a) => s + (a.timeTotSec > 0 ? (a.epCur??0)*a.timeTotSec : (a.epCur??0)*1440), 0);
  const wh = Math.floor(totalSecs/3600), wm = Math.floor((totalSecs%3600)/60);

  const scored    = list.filter(a=>a.score);
  const meanScore = scored.length ? (scored.reduce((s,a)=>s+(a.score??0),0)/scored.length).toFixed(1) : '—';
  const compRate  = total ? Math.round(finished/total*100) : 0;
  const dropRate  = total ? (dropped/total*100).toFixed(1) : '0';

  const scoreDist = Array(10).fill(0);
  scored.forEach(a => { if(a.score>=1&&a.score<=10) scoreDist[a.score-1]++; });
  const maxDist   = Math.max(...scoreDist, 1);

  const donutData = [
    { label:'Watching',     val:watching, color:'var(--watching)' },
    { label:'Completed',    val:finished, color:'var(--finished)' },
    { label:'On Hold',      val:onHold,   color:'var(--hold)' },
    { label:'Dropped',      val:dropped,  color:'var(--dropped)' },
    { label:'Plan to Watch',val:planned,  color:'var(--plan)' },
  ].filter(d=>d.val>0);

  const fmtMap = {}; list.forEach(a=>{ if(a.format){ fmtMap[a.format]=(fmtMap[a.format]||0)+1; } });
  const fmtSorted = Object.entries(fmtMap).sort((a,b)=>b[1]-a[1]);

  const genreMap = {}; list.forEach(a=>{ (a.genres||[]).forEach(g=>{ genreMap[g]=(genreMap[g]||0)+1; }); });
  const genreTop = Object.entries(genreMap).sort((a,b)=>b[1]-a[1]).slice(0,8);

  const studioMap = {}; list.forEach(a=>{ if(a.studio) studioMap[a.studio]=(studioMap[a.studio]||0)+1; });
  const topStudio = Object.entries(studioMap).sort((a,b)=>b[1]-a[1])[0];

  body.innerHTML = `
    <div class="sp-card wide">
      <h3>Overview</h3>
      <div class="sp-big">
        <div class="sp-stat"><div class="n">${total}</div><div class="l">Shows</div></div>
        <div class="sp-stat"><div class="n">${totalEps.toLocaleString()}</div><div class="l">Episodes</div></div>
        <div class="sp-stat"><div class="n">${wh}h ${wm}m</div><div class="l">Watch Time</div></div>
        <div class="sp-stat"><div class="n">${meanScore}</div><div class="l">Mean Score</div></div>
        <div class="sp-stat"><div class="n">${compRate}%</div><div class="l">Completion</div></div>
        <div class="sp-stat"><div class="n">${dropRate}%</div><div class="l">Drop Rate</div></div>
        ${topStudio?`<div class="sp-stat"><div class="n" style="font-size:18px">${x(topStudio[0])}</div><div class="l">Top Studio</div></div>`:''}
      </div>
    </div>
    <div class="sp-card">
      <h3>Collection Status</h3>
      <div class="donut-wrap">
        ${buildDonut(donutData, total)}
        <div class="donut-legend">
          ${donutData.map(d=>`<div class="dl-item"><div class="dl-dot" style="background:${d.color}"></div><span style="color:var(--text2)">${d.label}</span><span class="dl-val">${d.val}</span></div>`).join('')}
        </div>
      </div>
    </div>
    <div class="sp-card">
      <h3>Score Distribution</h3>
      <div class="score-bars">
        ${scoreDist.map((v,i)=>`<div class="sb-col"><div class="sb-bar" style="height:${Math.round(v/maxDist*70)+2}px" title="${v} anime"></div><div class="sb-lbl">${i+1}</div></div>`).join('')}
      </div>
    </div>
    ${fmtSorted.length?`<div class="sp-card"><h3>Shows by Type</h3>${fmtSorted.map(([f,v])=>`<div class="bar-row"><span class="bar-label">${f}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.round(v/fmtSorted[0][1]*100)}%"></div></div><span class="bar-val">${v}</span></div>`).join('')}</div>`:''}
    ${genreTop.length?`<div class="sp-card wide"><h3>Genre Preferences</h3><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px">${genreTop.map(([g,v])=>`<div><div style="display:flex;justify-content:space-between;font-size:.78rem;margin-bottom:4px"><span style="color:var(--text2)">${x(g)}</span><span style="color:var(--text);font-weight:600">${v}</span></div><div class="bar-track"><div class="bar-fill" style="width:${Math.round(v/genreTop[0][1]*100)}%"></div></div></div>`).join('')}</div></div>`:''}
  `;
}

function buildDonut(data, total) {
  const R = 54, CX = 64, CY = 64, stroke = 18, circ = 2 * Math.PI * R;
  let offset = 0, segs = '';
  data.forEach(d => {
    const dash = (d.val / total) * circ;
    segs += `<circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="${d.color}" stroke-width="${stroke}" stroke-dasharray="${dash} ${circ - dash}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${CX} ${CY})"/>`;
    offset += dash;
  });
  return `<svg width="128" height="128" viewBox="0 0 128 128" style="flex-shrink:0"><circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="var(--border)" stroke-width="${stroke}"/>${segs}<text x="${CX}" y="${CY+6}" text-anchor="middle" font-size="18" font-family="Bebas Neue,sans-serif" fill="var(--text)">${total}</text></svg>`;
}

function x(s){return String(s??'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function xe(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function sid(s){return String(s).replace(/[^a-zA-Z0-9]/g,'_');}
function t2s(str=''){const p=String(str).trim().split(':').map(Number);if(p.length===3)return p[0]*3600+p[1]*60+p[2];if(p.length===2)return p[0]*60+p[1];return 0;}
function s2t(sec){const h=Math.floor(sec/3600),m=Math.floor((sec%3600)/60),s=sec%60;return h>0?`${h}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`:`${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;}
function dl(c,n,m){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([c],{type:m}));a.download=n;document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(a.href);}