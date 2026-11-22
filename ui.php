<?php
require_once __DIR__ . '/_config.php';

if (session_status() !== PHP_SESSION_ACTIVE) session_start();
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));

function ui_e($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$user = $_SESSION['github_user'] ?? null;
$isAdmin = $user && in_array($user, $ADMIN_USERS, true);
$csrf = $_SESSION['csrf'];
$page = 'catalog';
$modId = '';
if (preg_match('#^/ui/mod/([^/]+)$#', $path, $match)) {
    $page = 'mod';
    $modId = rawurldecode($match[1]);
} elseif ($path === '/developers') {
    $page = 'developers';
} elseif ($path === '/install') {
    $page = 'install';
} elseif ($path === '/ui/admin') {
    $page = 'admin';
}
if ($page === 'admin' && !$isAdmin) {
    http_response_code(403);
    $page = 'forbidden';
}

$titles = [
    'catalog' => 'Mod catalog', 'mod' => 'Mod details', 'developers' => 'Developers',
    'install' => 'Installation', 'admin' => 'Administration', 'forbidden' => 'Access denied'
];
$title = $titles[$page] ?? 'Open Geode Index';
?><!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="<?=ui_e($csrf)?>">
  <meta name="description" content="<?=ui_e(SITE_DESCRIPTION)?>">
  <meta name="theme-color" content="#101318">
  <title><?=ui_e($title)?> · Open Geode Index</title>
  <link rel="icon" href="<?=ui_e(ICON_URL)?>">
  <link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" crossorigin="anonymous">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
  <style>
    :root{--ogi-bg:#101318;--ogi-panel:#171b22;--ogi-panel-2:#1d232c;--ogi-border:#2a313c;--ogi-accent:#88aaff}
    body{min-height:100vh;background:var(--ogi-bg);color:#e7eaf0}
    .navbar{background:rgba(16,19,24,.96);backdrop-filter:blur(12px)}
    .navbar-brand{font-weight:750;letter-spacing:-.03em}.brand-mark{display:inline-grid;place-items:center;width:2rem;height:2rem;border-radius:.55rem;background:#25385e;color:#a8c0ff;margin-right:.55rem}
    .app-shell{max-width:1440px}.page-heading{letter-spacing:-.04em;font-weight:750}.eyebrow{text-transform:uppercase;letter-spacing:.13em;font-size:.72rem;font-weight:700;color:#9da8ba}
    .panel,.mod-card,.stat-card{background:var(--ogi-panel);border:1px solid var(--ogi-border);border-radius:.85rem}
    .mod-card{height:100%;transition:border-color .15s,transform .15s}.mod-card:hover{border-color:#52698d;transform:translateY(-2px)}
    .mod-logo{width:3.5rem;height:3.5rem;object-fit:cover;border-radius:.65rem;background:var(--ogi-panel-2)}
    .tag-chip{font-size:.72rem;border:1px solid var(--ogi-border);border-radius:999px;padding:.2rem .55rem;color:#bac4d3;background:#1a2029}
    .tag-filter{border:1px solid var(--ogi-border);border-radius:999px;background:transparent;color:#bec8d8;padding:.35rem .7rem;font-size:.8rem}
    .tag-filter:hover,.tag-filter.active{border-color:#7899df;background:#243654;color:#dce7ff}
    .stat-card{padding:1rem 1.15rem}.stat-number{font-size:1.55rem;font-weight:750;line-height:1.1}
    .form-control,.form-select{border-color:#353d49}.form-control:focus,.form-select:focus{border-color:#7899df;box-shadow:0 0 0 .2rem rgba(120,153,223,.15)}
    .empty-state{border:1px dashed var(--ogi-border);border-radius:.85rem;padding:3rem 1rem;text-align:center;color:#aab4c3}
    .skeleton{height:150px;border-radius:.85rem;background:linear-gradient(90deg,#191e26,#222936,#191e26);background-size:200% 100%;animation:shimmer 1.3s infinite}
    @keyframes shimmer{to{background-position:-200% 0}}
    .markdown-text{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.75;color:#c5ccd7}
    .section-label{font-size:.78rem;text-transform:uppercase;letter-spacing:.1em;color:#9da8ba;font-weight:700}
    footer{border-top:1px solid var(--ogi-border);color:#8792a3}
    @media(max-width:767.98px){.hero-title{font-size:2rem}.navbar .container{padding-left:1rem;padding-right:1rem}}
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg border-bottom border-secondary-subtle sticky-top">
  <div class="container app-shell">
    <a class="navbar-brand text-light d-flex align-items-center" href="/ui"><span class="brand-mark"><i class="bi bi-boxes"></i></span>Open Geode Index</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#siteNav" aria-controls="siteNav" aria-expanded="false" aria-label="Toggle navigation"><span class="navbar-toggler-icon"></span></button>
    <div class="collapse navbar-collapse" id="siteNav">
      <ul class="navbar-nav me-auto ms-lg-4 gap-lg-2">
        <li class="nav-item"><a class="nav-link <?=in_array($page,['catalog','mod'],true)?'active':''?>" href="/ui"><i class="bi bi-grid me-1"></i>Catalog</a></li>
        <li class="nav-item"><a class="nav-link <?=$page==='developers'?'active':''?>" href="/developers"><i class="bi bi-people me-1"></i>Developers</a></li>
        <li class="nav-item"><a class="nav-link <?=$page==='install'?'active':''?>" href="/install"><i class="bi bi-download me-1"></i>Install</a></li>
        <?php if ($isAdmin): ?><li class="nav-item"><a class="nav-link <?=$page==='admin'?'active':''?>" href="/ui/admin"><i class="bi bi-shield-lock me-1"></i>Admin</a></li><?php endif; ?>
      </ul>
      <div class="d-flex align-items-center gap-2 py-2 py-lg-0">
        <?php if ($user): ?><a class="btn btn-sm btn-outline-secondary" href="https://github.com/<?=rawurlencode($user)?>" target="_blank" rel="noopener"><i class="bi bi-github me-1"></i><?=ui_e($user)?></a><a class="btn btn-sm btn-outline-danger" href="/logout">Sign out</a>
        <?php else: ?><a class="btn btn-sm btn-light" href="/login"><i class="bi bi-github me-1"></i>Sign in</a><?php endif; ?>
      </div>
    </div>
  </div>
</nav>
<main class="container app-shell py-4 py-lg-5">
<?php if ($page === 'catalog'): ?>
  <section class="row g-4 align-items-stretch mb-4">
    <div class="col-lg-8">
      <div class="panel h-100 p-4 p-lg-5">
        <div class="eyebrow mb-2">Independent community catalog</div>
        <h1 class="page-heading hero-title mb-3">Find the mods you need.</h1>
        <p class="text-secondary mb-4" style="max-width:48rem">Browse, filter and install mods for Geode. Search by name, ID, description or tag; open a listing for version and developer information.</p>
        <div class="d-flex flex-wrap gap-2"><a class="btn btn-primary" href="#catalog"><i class="bi bi-search me-2"></i>Browse catalog</a><a class="btn btn-outline-secondary" href="/install">Installation guide</a></div>
      </div>
    </div>
    <div class="col-lg-4"><div class="panel h-100 p-4">
      <div class="eyebrow mb-3">Index at a glance</div>
      <div class="row g-3">
        <div class="col-6"><div class="stat-card h-100"><div class="text-secondary small mb-2">Listed mods</div><div class="stat-number" id="stat-mods">—</div></div></div>
        <div class="col-6"><div class="stat-card h-100"><div class="text-secondary small mb-2">Developers</div><div class="stat-number" id="stat-devs">—</div></div></div>
      </div>
      <p class="small text-secondary mt-3 mb-0">Catalog data is provided by the Open Geode Index API.</p>
    </div></div>
  </section>
  <section id="catalog" class="row g-4">
    <aside class="col-lg-3">
      <div class="panel p-3 p-lg-4 sticky-lg-top" style="top:6.25rem">
        <div class="d-flex justify-content-between align-items-center mb-3"><h2 class="h5 mb-0">Filters</h2><button class="btn btn-sm btn-link text-decoration-none p-0" id="clear-filters">Reset</button></div>
        <label for="search" class="form-label small text-secondary">Search</label>
        <div class="input-group mb-3"><span class="input-group-text bg-transparent"><i class="bi bi-search"></i></span><input id="search" class="form-control" placeholder="Name, ID, keyword…" autocomplete="off"><button id="search-submit" class="btn btn-outline-secondary" aria-label="Search"><i class="bi bi-arrow-return-left"></i></button></div>
        <label for="sort" class="form-label small text-secondary">Sort by</label>
        <select id="sort" class="form-select mb-3"><option value="downloads">Most downloaded</option><option value="recently_updated">Recently updated</option><option value="recently_published">Recently published</option><option value="name">ID: A–Z</option><option value="name_reverse">ID: Z–A</option><option value="oldest">Oldest</option></select>
        <label for="per-page" class="form-label small text-secondary">Results per page</label>
        <select id="per-page" class="form-select mb-4"><option value="12">12</option><option value="24" selected>24</option><option value="48">48</option><option value="96">96</option></select>
        <div class="d-flex justify-content-between align-items-center mb-2"><span class="section-label">Tags</span><span class="small text-secondary" id="tag-status">Loading</span></div>
        <div id="tag-list" class="d-flex flex-wrap gap-2"><span class="text-secondary small">Loading tags…</span></div>
      </div>
    </aside>
    <div class="col-lg-9">
      <div class="d-flex flex-wrap justify-content-between align-items-end gap-2 mb-3"><div><div class="eyebrow">Browse</div><h2 class="h3 page-heading mb-0">Mod catalog</h2></div><div class="small text-secondary" id="result-count" aria-live="polite">Loading catalog…</div></div>
      <div id="mod-grid" class="row g-3" aria-live="polite"></div>
      <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mt-4"><div class="small text-secondary" id="page-status"></div><nav aria-label="Catalog pages"><ul class="pagination pagination-sm mb-0"><li class="page-item"><button class="page-link" id="prev-page">Previous</button></li><li class="page-item"><button class="page-link" id="next-page">Next</button></li></ul></nav></div>
    </div>
  </section>
  <script>
  (()=>{
    const state={query:'',tags:[],sort:'downloads',perPage:24,page:1,total:0,loading:false};
    const $=id=>document.getElementById(id), grid=$('mod-grid');
    const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const params=new URLSearchParams(location.search);
    state.query=params.get('query')||''; state.tags=(params.get('tags')||'').split(',').filter(Boolean);
    if(['downloads','recently_updated','recently_published','name','name_reverse','oldest'].includes(params.get('sort')))state.sort=params.get('sort');
    if([12,24,48,96].includes(Number(params.get('per_page'))))state.perPage=Number(params.get('per_page'));
    state.page=Math.max(1,Number(params.get('page'))||1);
    $('search').value=state.query;$('sort').value=state.sort;$('per-page').value=state.perPage;
    function updateUrl(){const p=new URLSearchParams();if(state.query)p.set('query',state.query);if(state.tags.length)p.set('tags',state.tags.join(','));if(state.sort!=='downloads')p.set('sort',state.sort);if(state.perPage!==24)p.set('per_page',state.perPage);if(state.page>1)p.set('page',state.page);history.replaceState({},'',location.pathname+(p.toString()?'?'+p:''));}
    function skeletons(){grid.innerHTML=Array.from({length:6},()=>'<div class="col-md-6"><div class="skeleton"></div></div>').join('');}
    function renderTags(tags){const items=(tags||[]).map(t=>typeof t==='string'?t:(t.name||t.display_name||'')).filter(Boolean);$('tag-status').textContent=items.length?`${items.length} available`:'None';$('tag-list').innerHTML=items.map(t=>`<button type="button" class="tag-filter ${state.tags.includes(t)?'active':''}" data-tag="${esc(t)}" aria-pressed="${state.tags.includes(t)}">${esc(t)}</button>`).join('')||'<span class="small text-secondary">No tags available.</span>';}
    async function loadTags(){try{const r=await fetch('/v1/detailed-tags');if(!r.ok)throw Error();const d=await r.json();renderTags(d.payload||[]);}catch{$('tag-status').textContent='Unavailable';$('tag-list').innerHTML='<span class="small text-secondary">Could not load tags.</span>';}}
    function renderMods(mods){if(!mods.length){grid.innerHTML='<div class="col-12"><div class="empty-state"><i class="bi bi-search fs-2 d-block mb-2"></i><strong>No matching mods</strong><div class="small mt-1">Try a different search or remove some filters.</div></div></div>';return;}
      grid.innerHTML=mods.map(m=>{const v=m.versions?.[0]||{}, name=v.name||m.name||m.id||'Unnamed mod',desc=v.description||m.about||'',tags=(m.tags||[]).slice(0,4);return `<div class="col-md-6"><a class="mod-card text-decoration-none text-reset d-block p-3" href="/ui/mod/${encodeURIComponent(m.id||'')}"><div class="d-flex gap-3"><img class="mod-logo flex-shrink-0" src="${esc(m.logo_url||'')}" alt="" loading="lazy" onerror="this.style.visibility='hidden'"><div class="min-w-0 flex-grow-1"><div class="d-flex justify-content-between gap-2"><h3 class="h6 fw-bold mb-1 text-truncate">${esc(name)}</h3><span class="small text-secondary text-nowrap"><i class="bi bi-download me-1"></i>${Number(m.download_count||0).toLocaleString()}</span></div><div class="small text-secondary text-truncate mb-2">${esc(m.id||'')}</div><p class="small text-secondary mb-2" style="display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden">${esc(desc.replace(/<[^>]*>/g,' '))}</p><div class="d-flex flex-wrap gap-1">${tags.map(t=>`<span class="tag-chip">${esc(t)}</span>`).join('')}</div></div></div></a></div>`;}).join('');}
    async function fetchMods(){if(state.loading)return;state.loading=true;skeletons();$('result-count').textContent='Loading…';const p=new URLSearchParams({sort:state.sort,page:state.page,per_page:state.perPage});if(state.query)p.set('query',state.query);if(state.tags.length)p.set('tags',state.tags.join(','));try{const r=await fetch('/v1/mods?'+p);if(!r.ok)throw Error('Request failed ('+r.status+')');const d=await r.json();if(d.error)throw Error(d.error);const payload=d.payload||{};state.total=Number(payload.count||0);renderMods(payload.data||[]);const pages=Math.max(1,Math.ceil(state.total/state.perPage));if(state.page>pages){state.page=pages;updateUrl();state.loading=false;return fetchMods();}$('result-count').textContent=`${state.total.toLocaleString()} result${state.total===1?'':'s'}`;$('page-status').textContent=`Page ${state.page} of ${pages}`;$('prev-page').disabled=state.page<=1;$('next-page').disabled=state.page>=pages;updateUrl();}catch(e){grid.innerHTML=`<div class="col-12"><div class="alert alert-danger mb-0"><i class="bi bi-exclamation-triangle me-2"></i>${esc(e.message||'Unable to load catalog.')}</div></div>`;$('result-count').textContent='Catalog unavailable';}finally{state.loading=false;}}
    function apply(){state.query=$('search').value.trim();state.sort=$('sort').value;state.perPage=Number($('per-page').value)||24;state.page=1;fetchMods();}
    $('tag-list').addEventListener('click',e=>{const b=e.target.closest('[data-tag]');if(!b)return;const t=b.dataset.tag;state.tags=state.tags.includes(t)?state.tags.filter(x=>x!==t):[...state.tags,t];state.page=1;renderTags([...document.querySelectorAll('#tag-list [data-tag]')].map(x=>x.dataset.tag));fetchMods();});
    $('search-submit').addEventListener('click',apply);$('search').addEventListener('keydown',e=>{if(e.key==='Enter')apply();});$('sort').addEventListener('change',apply);$('per-page').addEventListener('change',apply);$('prev-page').addEventListener('click',()=>{if(state.page>1){state.page--;fetchMods();}});$('next-page').addEventListener('click',()=>{state.page++;fetchMods();});$('clear-filters').addEventListener('click',()=>{state.tags=[];$('search').value='';$('sort').value='downloads';$('per-page').value='24';state.query='';state.sort='downloads';state.perPage=24;state.page=1;fetchMods();loadTags();});
    Promise.all([loadTags(),fetchMods()]);fetch('/v1/stats').then(r=>r.json()).then(d=>{const s=d.payload||{};$('stat-mods').textContent=Number(s.total_mod_count||0).toLocaleString();$('stat-devs').textContent=Number(s.total_registered_developers||0).toLocaleString();}).catch(()=>{});
  })();
  </script>
<?php elseif ($page === 'mod'): ?>
  <div class="mb-4"><a href="/ui" class="link-secondary text-decoration-none"><i class="bi bi-arrow-left me-1"></i>Back to catalog</a></div>
  <div id="mod-detail"><div class="skeleton" style="height:320px"></div></div>
  <script>
  (()=>{const root=document.getElementById('mod-detail'),id=<?=json_encode($modId, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_AMP)?>;const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));fetch('/v1/mods/'+encodeURIComponent(id)).then(async r=>{const d=await r.json();if(!r.ok||d.error)throw Error(d.error||'Mod not found');return d.payload;}).then(m=>{const versions=m.versions||[],latest=versions[0]||{},developers=m.developers||[],tags=m.tags||[];document.title=(latest.name||m.id)+' · Open Geode Index';root.innerHTML=`<div class="row g-4"><div class="col-lg-8"><div class="panel p-4 p-lg-5"><div class="d-flex gap-3 align-items-start mb-4"><img class="mod-logo" style="width:5rem;height:5rem" src="${esc(m.logo_url||'')}" alt="" onerror="this.style.visibility='hidden'"><div class="min-w-0"><div class="eyebrow">Mod listing</div><h1 class="page-heading h2 mb-1">${esc(latest.name||m.id)}</h1><div class="text-secondary font-monospace">${esc(m.id)}</div>${latest.description?`<p class="text-secondary mt-2 mb-0">${esc(latest.description)}</p>`:''}</div></div><div class="d-flex flex-wrap gap-2 mb-4">${tags.map(t=>`<span class="tag-chip">${esc(t)}</span>`).join('')}</div><h2 class="section-label mb-3">About</h2><div class="markdown-text">${esc(m.about||'No description has been provided.')}</div>${m.changelog?`<hr class="my-4"><h2 class="section-label mb-3">Changelog</h2><div class="markdown-text">${esc(m.changelog)}</div>`:''}</div></div><aside class="col-lg-4"><div class="panel p-4 mb-3"><div class="d-flex justify-content-between align-items-center mb-3"><h2 class="h5 mb-0">Versions</h2><span class="badge text-bg-secondary">${versions.length}</span></div>${versions.length?`<div class="list-group list-group-flush">${versions.map((v,i)=>`<div class="list-group-item bg-transparent px-0"><div class="d-flex justify-content-between align-items-start gap-2"><div><div class="fw-semibold">${esc(v.version||'Unknown')}${i===0?' <span class="badge text-bg-primary ms-1">Latest</span>':''}</div><div class="small text-secondary mt-1"><i class="bi bi-download me-1"></i>${Number(v.download_count||0).toLocaleString()} downloads</div></div><a class="btn btn-sm btn-primary" href="/v1/mods/${encodeURIComponent(m.id)}/versions/${encodeURIComponent(v.version)}/download"><i class="bi bi-download me-1"></i>Get</a></div></div>`).join('')}</div>`:'<p class="text-secondary mb-0">No versions listed.</p>'}</div><div class="panel p-4"><h2 class="h5 mb-3">Developers</h2>${developers.length?developers.map(d=>`<a class="d-flex align-items-center gap-3 text-decoration-none text-reset py-2 border-bottom border-secondary-subtle" href="https://github.com/${encodeURIComponent(d.username||'')}" target="_blank" rel="noopener"><img class="rounded" width="40" height="40" src="https://github.com/${encodeURIComponent(d.username||'')}.png" alt="" onerror="this.style.visibility='hidden'"><span class="flex-grow-1"><span class="d-block fw-semibold">${esc(d.display_name||d.username)}</span><span class="small text-secondary">@${esc(d.username)}</span></span><span class="badge ${d.is_owner?'text-bg-info':'text-bg-secondary'}">${esc(d.role||(d.is_owner?'Owner':'Developer'))}</span></a>`).join(''):'<p class="text-secondary mb-0">No developer information.</p>'}${m.repository?`<a class="btn btn-outline-secondary w-100 mt-3" href="https://github.com/${esc(m.repo||'')}" target="_blank" rel="noopener"><i class="bi bi-github me-2"></i>Source repository</a>`:''}</div></aside></div>`;}).catch(e=>{root.innerHTML=`<div class="alert alert-danger"><h1 class="h4">Could not load mod</h1><p class="mb-3">${esc(e.message)}</p><a href="/ui" class="btn btn-outline-light">Return to catalog</a></div>`;});})();
  </script>
<?php elseif ($page === 'developers'): ?>
  <div class="d-flex flex-wrap justify-content-between align-items-end gap-3 mb-4"><div><div class="eyebrow">Community</div><h1 class="page-heading h2 mb-1">Developers</h1><p class="text-secondary mb-0">People with a developer profile in the index.</p></div><div class="input-group" style="max-width:22rem"><span class="input-group-text bg-transparent"><i class="bi bi-search"></i></span><input id="developer-search" class="form-control" placeholder="Filter by username or name"></div></div>
  <div id="developer-list" class="row g-3"><div class="col-12"><div class="skeleton" style="height:72px"></div></div></div>
  <script>(()=>{const el=document.getElementById('developer-list'),input=document.getElementById('developer-search');let people=[];const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));function render(){const q=input.value.toLowerCase();const list=people.filter(x=>(x.username+' '+(x.display_name||'')).toLowerCase().includes(q));el.innerHTML=list.length?list.map(x=>`<div class="col-sm-6 col-xl-4"><div class="panel p-3 h-100 d-flex align-items-center gap-3"><img src="https://github.com/${encodeURIComponent(x.username)}.png" width="48" height="48" class="rounded" alt="" onerror="this.style.visibility='hidden'"><div class="min-w-0"><a class="fw-semibold text-decoration-none" href="https://github.com/${encodeURIComponent(x.username)}" target="_blank" rel="noopener">${esc(x.display_name||x.username)}</a><div class="small text-secondary text-truncate">@${esc(x.username)}</div>${x.verified?'<span class="badge text-bg-info mt-1">Verified</span>':''}</div></div></div>`).join(''):'<div class="col-12"><div class="empty-state">No developers match this search.</div></div>';}input.addEventListener('input',render);fetch('/v1/developers?per_page=200').then(r=>r.json()).then(d=>{people=d.payload?.data||[];render();}).catch(()=>{el.innerHTML='<div class="col-12"><div class="alert alert-danger">Unable to load developer profiles.</div></div>';});})();</script>
<?php elseif ($page === 'install'): ?>
  <div class="row justify-content-center"><div class="col-lg-9"><div class="eyebrow">Getting started</div><h1 class="page-heading h2 mb-2">Use Open Geode Index</h1><p class="text-secondary mb-4">Connect Geode to this catalog with the proxy mod, or use the API directly.</p>
    <div class="panel p-4 p-lg-5 mb-3"><div class="d-flex gap-3"><span class="brand-mark flex-shrink-0"><i class="bi bi-1-circle"></i></span><div><h2 class="h5">Install the proxy mod</h2><p class="text-secondary">Install the Open Geode Index proxy mod in Geode Loader. Follow the project’s setup notes for your platform.</p><a class="btn btn-primary" href="https://github.com/lil2kki/Open-Geode-Index#how-to-install" target="_blank" rel="noopener"><i class="bi bi-box-arrow-up-right me-2"></i>Open installation instructions</a></div></div></div>
    <div class="panel p-4 p-lg-5 mb-3"><div class="d-flex gap-3"><span class="brand-mark flex-shrink-0"><i class="bi bi-2-circle"></i></span><div><h2 class="h5">Set the catalog source</h2><p class="text-secondary mb-0">In Geode settings, set the mod source to this site’s URL, then restart Geode and browse the available mods.</p><code class="d-inline-block mt-3 p-2 rounded bg-black">https://<?=ui_e($_SERVER['HTTP_HOST']??'open-geode-index.bccst.ru')?></code></div></div></div>
    <div class="panel p-4 p-lg-5"><div class="d-flex gap-3"><span class="brand-mark flex-shrink-0"><i class="bi bi-code-slash"></i></span><div><h2 class="h5">Use the API</h2><p class="text-secondary">The API is available under <code>/v1</code>. Check service status or explore developer profiles.</p><div class="d-flex gap-2"><a class="btn btn-outline-secondary" href="/health"><i class="bi bi-heart-pulse me-2"></i>Service health</a><a class="btn btn-outline-secondary" href="/developers">Developer directory</a></div></div></div></div>
  </div></div>
<?php elseif ($page === 'admin'): ?>
  <div class="mb-4"><div class="eyebrow">Restricted area</div><h1 class="page-heading h2 mb-1">Administration</h1><p class="text-secondary mb-0">Review catalog totals and manage featured listings.</p></div>
  <div class="row g-3 mb-4"><div class="col-sm-4"><div class="stat-card"><div class="small text-secondary mb-2">Mods</div><div class="stat-number" id="admin-mod-count">—</div></div></div><div class="col-sm-4"><div class="stat-card"><div class="small text-secondary mb-2">Developers</div><div class="stat-number" id="admin-dev-count">—</div></div></div><div class="col-sm-4"><div class="stat-card"><div class="small text-secondary mb-2">Featured</div><div class="stat-number" id="admin-featured-count">—</div></div></div></div>
  <div class="panel p-3 p-lg-4"><div class="d-flex flex-wrap justify-content-between gap-2 align-items-center mb-3"><h2 class="h5 mb-0">Mod listings</h2><span class="small text-secondary">Feature status changes immediately after submission.</span></div><div class="table-responsive"><table class="table table-hover align-middle mb-0"><thead><tr><th>Mod ID</th><th>Name</th><th>Versions</th><th>Downloads</th><th>Featured</th><th></th></tr></thead><tbody id="admin-mods"><tr><td colspan="6" class="text-secondary">Loading listings…</td></tr></tbody></table></div></div>
  <script>(()=>{const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const csrf=document.querySelector('meta[name="csrf-token"]').content;Promise.all([fetch('/v1/stats').then(r=>r.json()),fetch('/v1/mods?per_page=200&sort=name').then(r=>r.json())]).then(([stats,mods])=>{const s=stats.payload||{},data=mods.payload?.data||[];document.getElementById('admin-mod-count').textContent=s.total_mod_count||0;document.getElementById('admin-dev-count').textContent=s.total_registered_developers||0;document.getElementById('admin-featured-count').textContent=s.featured_count||0;const body=document.getElementById('admin-mods');body.innerHTML=data.length?data.map(m=>`<tr><td><a href="/ui/mod/${encodeURIComponent(m.id)}" class="font-monospace text-decoration-none">${esc(m.id)}</a></td><td>${esc(m.versions?.[0]?.name||'')}</td><td>${(m.versions||[]).length}</td><td>${Number(m.download_count||0).toLocaleString()}</td><td><span class="badge ${m.featured?'text-bg-success':'text-bg-secondary'}">${m.featured?'Featured':'Standard'}</span></td><td><form method="post" action="/ui/admin"><input type="hidden" name="csrf" value="${esc(csrf)}"><input type="hidden" name="mod_id" value="${esc(m.id)}"><input type="hidden" name="action" value="toggle_featured"><button class="btn btn-sm btn-outline-secondary">${m.featured?'Unfeature':'Feature'}</button></form></td></tr>`).join(''):'<tr><td colspan="6" class="text-secondary">No local listings.</td></tr>';}).catch(()=>{document.getElementById('admin-mods').innerHTML='<tr><td colspan="6" class="text-danger">Could not load admin data.</td></tr>';});})();</script>
<?php else: ?>
  <div class="row justify-content-center"><div class="col-lg-6"><div class="panel p-4 p-lg-5 text-center"><i class="bi bi-shield-lock fs-1 text-secondary"></i><h1 class="page-heading h3 mt-3">Access denied</h1><p class="text-secondary">You don’t have permission to view this page.</p><a class="btn btn-outline-light" href="/ui">Return to catalog</a></div></div></div>
<?php endif; ?>
</main>
<footer class="mt-5 py-4"><div class="container app-shell d-flex flex-wrap justify-content-between gap-2 small"><span>Open Geode Index · Community mod catalog</span><span><a class="link-secondary" href="https://github.com/lil2kki/Open-Geode-Index" target="_blank" rel="noopener">Project source</a><span class="mx-2">·</span><a class="link-secondary" href="/health">Service status</a></span></div></footer>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
</body>
</html>
