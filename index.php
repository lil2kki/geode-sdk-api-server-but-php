<?php
include '_config.php';

define('DATA_DIR', __DIR__ . '/data');
define('SESSION_COOKIE', 'ogi_session');
define('ACCESS_TOKEN_TTL', 60 * 60 * 24 * 7);
define('REFRESH_TOKEN_TTL', 60 * 60 * 24 * 30);
// [PATCH] Поставь DEBUG true только локально — включает pretty-print JSON и подробные ошибки
define('DEBUG', false);
define('MAX_UPLOAD_BYTES', 120 * 1024 * 1024);
define('UPSTREAM_CACHE_TTL', 300);

@ini_set('display_errors', DEBUG ? '1' : '0');
@ini_set('display_startup_errors', DEBUG ? '1' : '0');

ob_start();

if (!file_exists(DATA_DIR)) @mkdir(DATA_DIR, 0755, true);

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Upstream-Url, X-CSRF-Token');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

session_start();

/* ======================= [PATCH] SECURITY & INFRA ======================= */

// CSRF-токен на сессию
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
define('CSRF_TOKEN', $_SESSION['csrf']);

function csrf_check_if_session() {
    // Bearer-токены CSRF не подвержены, проверяем только сессионные действия
    if (empty($_SESSION['github_user'])) return;
    $sent = $_POST['csrf'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    if (!hash_equals(CSRF_TOKEN, (string)$sent)) {
        json_response(['error' => 'CSRF token mismatch', 'payload' => null], 403);
    }
}

// Простой файловый rate-limiter по IP. $bucket — своё пространство имён.
function rate_limit($bucket, $max = 300, $window = 60) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $key = $bucket . ':' . $ip;
    $data = db_read('ratelimit.json') ?: [];
    $now = time();

    // Периодическая очистка
    if (mt_rand(1, 50) === 1) {
        foreach ($data as $k => $v) if (($v['reset'] ?? 0) < $now) unset($data[$k]);
    }

    $b = $data[$key] ?? ['count' => 0, 'reset' => $now + $window];
    if ($now > $b['reset']) $b = ['count' => 0, 'reset' => $now + $window];
    $b['count']++;
    $data[$key] = $b;
    db_write('ratelimit.json', $data);

    if ($b['count'] > $max) {
        header('Retry-After: ' . max(1, $b['reset'] - $now));
        json_response(['error' => 'rate limit exceeded', 'payload' => null], 429);
    }
}

function api_log($action, $data = []) {
    $line = json_encode([
        'ts'     => gmdate('Y-m-d\TH:i:s\Z'),
        'ip'     => $_SERVER['REMOTE_ADDR'] ?? null,
        'method' => $_SERVER['REQUEST_METHOD'] ?? null,
        'uri'    => $_SERVER['REQUEST_URI'] ?? null,
        'user'   => current_user(),
        'action' => $action,
        'data'   => $data,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    @file_put_contents(DATA_DIR . '/access.log', $line . "\n", FILE_APPEND | LOCK_EX);
}

// [PATCH] Защита от SSRF. Разрешаем только http/https и публичные IP.
function is_safe_url($url) {
    if (empty($url) || !is_string($url)) return false;
    $p = @parse_url($url);
    if (!$p) return false;

    $scheme = strtolower($p['scheme'] ?? '');
    if (!in_array($scheme, ['http', 'https'], true)) return false;

    $host = $p['host'] ?? '';
    if ($host === '') return false;

    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ips[] = $host;
    } else {
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $r) {
                if (!empty($r['ip']))   $ips[] = $r['ip'];
                if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
            }
        }
        if (!$ips) {
            $resolved = @gethostbyname($host);
            if ($resolved && $resolved !== $host) $ips[] = $resolved;
        }
    }

    if (!$ips) return false;
    foreach ($ips as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
        // Отсекаем private/reserved/loopback/link-local
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
    }
    return true;
}

/* ======================= BOOT ======================= */

$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($uri !== '/' && substr($uri, -1) === '/') $uri = rtrim($uri, '/');

// [PATCH] Глобальный rate limit. GET/HEAD — щедро, остальное — строже.
rate_limit('global', ($method === 'GET' || $method === 'HEAD') ? 600 : 120, 60);

route($method, $uri);

/* ======================= ROUTER ======================= */
function route($method, $uri) {
    if ($uri === '/' && $method === 'GET') return handle_home();
    if ($uri === '/ui' && $method === 'GET') return render_ui();
    if ($uri === '/developers' && $method === 'GET') return render_devs();
    if ($uri === '/install' && $method === 'GET') return render_install();
    if ($uri === '/login' && $method === 'GET') return handle_login();
    if ($uri === '/callback' && $method === 'GET') return handle_callback();
    if ($uri === '/logout' && $method === 'GET') return handle_logout();
    if (preg_match('#^/ui/mod/([^/]+)$#', $uri, $m) && $method === 'GET') return render_mod_page($m[1]);
    if ($uri === '/ui/admin' && $method === 'GET') return render_admin_page();
    if ($uri === '/ui/admin' && $method === 'POST') return handle_admin_form();

    // [PATCH] расширенный /health
    if ($uri === '/health' && $method === 'GET') {
        $upstream_ok = false;
        if (defined('UPSTREAM_URL') && UPSTREAM_URL) {
            $h = @get_headers(UPSTREAM_URL . '/health');
            $upstream_ok = $h && preg_match('/\s2\d\d\s/', $h[0] ?? '');
        }
        header('Content-Type: application/json');
        echo json_encode([
            'status'            => 'ok',
            'time'              => gmdate('Y-m-d\TH:i:s\Z'),
            'data_dir_writable' => is_writable(DATA_DIR),
            'zip_available'     => class_exists('ZipArchive'),
            'upstream'          => $upstream_ok ? 'ok' : 'unreachable',
        ]);
        exit;
    }

    // tags (кэшируемые)
    if ($uri === '/v1/tags' && $method === 'GET') return api_tags_index();
    if ($uri === '/v1/detailed-tags' && $method === 'GET') return api_tags_detailed();

    // developers
    if ($uri === '/v1/developers' && $method === 'GET') return api_developers_index();
    if (preg_match('#^/v1/developers/(\d+)$#', $uri, $m)) {
        if ($method === 'GET') return api_developers_get(intval($m[1]));
        if ($method === 'PUT') { csrf_check_if_session(); return api_developers_update(intval($m[1])); }
    }

    // auth
    if ($uri === '/v1/login/github' && $method === 'POST') return api_login_github();
    if ($uri === '/v1/login/github/callback' && $method === 'POST') return api_login_callback();
    if ($uri === '/v1/login/github/poll' && $method === 'POST') return api_login_github_poll();
    if ($uri === '/v1/login/github/token' && $method === 'POST') return api_login_github_token();
    if ($uri === '/v1/login/github/web' && $method === 'POST') return api_login_github_web();
    if ($uri === '/v1/login/refresh' && $method === 'POST') return api_refresh_token();

    // me
    if ($uri === '/v1/me' && $method === 'GET') return api_get_me();
    if ($uri === '/v1/me' && $method === 'PUT') { csrf_check_if_session(); return api_put_me(); }
    if ($uri === '/v1/me/mods' && $method === 'GET') return api_get_own_mods();
    if ($uri === '/v1/me/token' && $method === 'DELETE') { csrf_check_if_session(); return api_delete_token(); }
    if ($uri === '/v1/me/tokens' && $method === 'DELETE') { csrf_check_if_session(); return api_delete_tokens(); }

    // loader versions
    if ($uri === '/v1/loader/versions' && $method === 'GET') return api_loader_versions_index();
    if ($uri === '/v1/loader/versions' && $method === 'POST') { csrf_check_if_session(); return api_loader_versions_create(); }
    if (preg_match('#^/v1/loader/versions/([^/]+)$#', $uri, $m) && $method === 'GET') return api_loader_versions_get($m[1]);

    // mods root
    if ($uri === '/v1/mods' && $method === 'GET') return api_mods_index();
    if ($uri === '/v1/mods' && $method === 'POST') { csrf_check_if_session(); return api_mods_create(); }

    if ($uri === '/v1/mods/updates' && $method === 'GET') return api_mods_updates();

    if (preg_match('#^/v1/mods/([^/]+)$#', $uri, $m)) {
        if ($method === 'GET') return api_mods_get($m[1]);
        if ($method === 'PUT') { csrf_check_if_session(); return api_mods_update_admin($m[1]); }
        if ($method === 'POST') {
            csrf_check_if_session();
            if (!empty($_POST['_method']) && strtoupper($_POST['_method']) === 'DELETE') return api_mods_delete($m[1]);
            return api_mods_update_owner($m[1]);
        }
        if ($method === 'DELETE') { csrf_check_if_session(); return api_mods_delete($m[1]); }
    }

    if (preg_match('#^/v1/mods/([^/]+)/deprecations$#', $uri, $m)) {
        if ($method === 'GET') return api_deprecations_index($m[1]);
        if ($method === 'POST') { csrf_check_if_session(); return api_deprecations_create($m[1]); }
        if ($method === 'DELETE') { csrf_check_if_session(); return api_deprecations_clear_all($m[1]); }
    }
    if (preg_match('#^/v1/mods/([^/]+)/deprecations/(\d+)$#', $uri, $m)) {
        if ($method === 'PUT') { csrf_check_if_session(); return api_deprecations_update($m[1], intval($m[2])); }
        if ($method === 'DELETE') { csrf_check_if_session(); return api_deprecations_delete($m[1], intval($m[2])); }
    }

    if (preg_match('#^/v1/mods/([^/]+)/developers$#', $uri, $m) && $method === 'POST') { csrf_check_if_session(); return api_mod_add_developer($m[1]); }
    if (preg_match('#^/v1/mods/([^/]+)/developers/([^/]+)$#', $uri, $m) && $method === 'DELETE') { csrf_check_if_session(); return api_mod_remove_developer($m[1], $m[2]); }

    if (preg_match('#^/v1/mods/([^/]+)/logo$#', $uri, $m) && $method === 'GET') return api_mod_logo($m[1]);

    if (preg_match('#^/v1/mods/([^/]+)/versions$#', $uri, $m)) {
        if ($method === 'GET') return api_mod_versions_index($m[1]);
        if ($method === 'POST') { csrf_check_if_session(); return api_mod_versions_create($m[1]); }
    }
    if (preg_match('#^/v1/mods/([^/]+)/versions/([^/]+)$#', $uri, $m)) {
        if ($method === 'GET') return api_mod_versions_get($m[1], $m[2]);
        if ($method === 'PUT') { csrf_check_if_session(); return api_mod_versions_update($m[1], $m[2]); }
    }
    if (preg_match('#^/v1/mods/([^/]+)/versions/([^/]+)/download$#', $uri, $m) && $method === 'GET') return api_mod_versions_download($m[1], $m[2]);

    if ($uri === '/v1/stats' && $method === 'GET') return api_stats();

    if (strpos($uri, '/v1') === 0) {
        json_response(['error' => 'not found', 'payload' => null], 404);
    } else {
        http_response_code(404);
        echo "<h1>404 Not Found</h1><p>" . htmlspecialchars($uri) . "</p>";
    }
    exit;
}

/* ======================= UTILITIES ======================= */

function md($a = 'a', $line = false) {
    if (!class_exists('Parsedown')) include 'Parsedown.php';
    return $line
        ? preg_replace('/^#+\s*/m', '', Parsedown::instance()->line($a))
        : Parsedown::instance()->text($a);
}

function compute_remote_sha256($url, $max_bytes = MAX_UPLOAD_BYTES, $timeout = 60, $max_redirects = 8) {
    if (empty($url) || stripos($url, 'http') !== 0) {
        error_log("[OGI] compute_remote_sha256 invalid url: $url");
        return null;
    }
    // [PATCH] SSRF
    if (!is_safe_url($url)) {
        error_log("[OGI] compute_remote_sha256 unsafe url: $url");
        return null;
    }

    $tmp = fetch_remote_file_to_temp($url, $max_bytes, $timeout, $max_redirects);
    if ($tmp === null) return null;

    $hash = @hash_file('sha256', $tmp);
    @unlink($tmp);
    return $hash === false ? null : $hash;
}

function fetch_remote_file_to_temp($url, $max_bytes = MAX_UPLOAD_BYTES, $timeout = 35, $max_redirects = 8) {
    if (empty($url) || stripos($url, 'http') !== 0) return null;
    if (!is_safe_url($url)) return null;

    $opts = [
        'http' => [
            'method'        => 'GET',
            'header'        => "User-Agent: Open-Geode-Index\r\nAccept: application/octet-stream\r\n",
            'timeout'       => $timeout,
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
    ];
    $ctx = stream_context_create($opts);
    $current = $url;
    $redirects = 0;

    while ($redirects <= $max_redirects) {
        $headers = @get_headers($current, 1, $ctx);
        if ($headers === false) return null;

        $statusLine = isset($headers[0]) ? (is_array($headers[0]) ? end($headers[0]) : $headers[0]) : null;
        $code = null;
        if ($statusLine && preg_match('/HTTP\/[\d\.]+\s+([0-9]{3})/i', $statusLine, $m)) $code = intval($m[1]);

        if ($code !== null && $code >= 300 && $code < 400 && !empty($headers['Location'])) {
            $loc = $headers['Location'];
            if (is_array($loc)) $loc = end($loc);
            if (parse_url($loc, PHP_URL_SCHEME) === null) {
                $base = parse_url($current);
                $scheme = $base['scheme'] ?? 'https';
                $host = $base['host'] ?? '';
                $port = isset($base['port']) ? ':' . $base['port'] : '';
                if (strpos($loc, '/') === 0) $loc = $scheme . '://' . $host . $port . $loc;
                else $loc = $scheme . '://' . $host . $port . (isset($base['path']) ? dirname($base['path']) . '/' : '') . $loc;
            }
            // [PATCH] каждый хоп редиректа тоже проверяем
            if (!is_safe_url($loc)) return null;
            $current = $loc;
            $redirects++;
            continue;
        }

        if ($code === null || $code < 200 || $code >= 300) return null;
        break;
    }
    if ($redirects > $max_redirects) return null;

    $fp = @fopen($current, 'rb', false, stream_context_create($opts));
    if ($fp === false) return null;

    $tmp = tempnam(sys_get_temp_dir(), 'ogi_');
    $out = @fopen($tmp, 'wb');
    if ($out === false) { fclose($fp); @unlink($tmp); return null; }

    $read = 0;
    while (!feof($fp) && $read < $max_bytes) {
        $data = @fread($fp, 8192);
        if ($data === false || $data === '') break;
        $read += strlen($data);
        fwrite($out, $data);
    }
    fclose($fp);
    fclose($out);

    if ($read >= $max_bytes) { @unlink($tmp); return null; }
    return $tmp;
}

function extract_metadata_from_geode($download_url) {
    if (empty($download_url)) return null;
    if (!is_safe_url($download_url)) return null;

    $tmp = fetch_remote_file_to_temp($download_url);
    if ($tmp === null) return null;

    if (!class_exists('ZipArchive')) { @unlink($tmp); return null; }

    $zip = new ZipArchive();
    if ($zip->open($tmp) !== true) { @unlink($tmp); return null; }

    $result = ['modjson' => null, 'about' => null, 'changelog' => null];
    $nameCount = $zip->numFiles;
    $found = ['mod.json' => null, 'about' => null, 'readme' => null, 'changelog' => null];

    for ($i = 0; $i < $nameCount; $i++) {
        $name = $zip->getNameIndex($i);
        $base = strtolower(basename($name));
        if ($base === 'mod.json' && $found['mod.json'] === null) $found['mod.json'] = $i;
        elseif (in_array($base, ['about.md', 'about', 'about.txt']) && $found['about'] === null) $found['about'] = $i;
        elseif (in_array($base, ['readme.md', 'readme', 'readme.txt']) && $found['readme'] === null) $found['readme'] = $i;
        elseif (in_array($base, ['changelog.md', 'changelog', 'change.log', 'changes.md']) && $found['changelog'] === null) $found['changelog'] = $i;
    }

    if ($found['mod.json'] !== null) {
        $raw = $zip->getFromIndex($found['mod.json']);
        if ($raw !== false) { $j = json_decode($raw, true); if ($j !== null) $result['modjson'] = $j; }
    }
    if ($found['about'] !== null) {
        $raw = $zip->getFromIndex($found['about']);
        if ($raw !== false) $result['about'] = $raw;
    } elseif ($found['readme'] !== null) {
        $raw = $zip->getFromIndex($found['readme']);
        if ($raw !== false) $result['about'] = $raw;
    }
    if ($found['changelog'] !== null) {
        $raw = $zip->getFromIndex($found['changelog']);
        if ($raw !== false) $result['changelog'] = $raw;
    }

    $zip->close();
    @unlink($tmp);
    return $result;
}

function json_response($data, $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json');
    $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
    if (DEBUG) $flags |= JSON_PRETTY_PRINT;
    echo json_encode($data, $flags);
    exit;
}

// [PATCH] JSON-ответ с ETag / 304. Для редко меняющихся эндпоинтов.
function json_response_etag($data, $status = 200, $ttl = 60) {
    $body = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $etag = '"' . md5($body) . '"';
    header('ETag: ' . $etag);
    header('Cache-Control: public, max-age=' . $ttl);
    if (($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === $etag) {
        http_response_code(304);
        exit;
    }
    http_response_code($status);
    header('Content-Type: application/json');
    echo $body;
    exit;
}

function db_read($file) {
    $path = DATA_DIR . '/' . $file;
    if (!file_exists($path)) return null;
    $s = @file_get_contents($path);
    if ($s === false) return null;
    return json_decode($s, true);
}

function db_write($file, $data) {
    $path = DATA_DIR . '/' . $file;
    $tmp = $path . '.tmp';
    $s = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    file_put_contents($tmp, $s, LOCK_EX);
    @rename($tmp, $path);
    return true;
}

function json_input() {
    $raw = file_get_contents('php://input');
    if (!empty($raw)) {
        $j = json_decode($raw, true);
        if ($j !== null) return $j;
        if (strpos($raw, '=') !== false) { parse_str($raw, $p); return $p; }
    }
    if (!empty($_POST)) {
        $p = $_POST;
        if (!empty($p['tags']) && !is_array($p['tags'])) {
            $p['tags'] = array_values(array_filter(array_map('trim', explode(',', $p['tags']))));
        }
        return $p;
    }
    return null;
}

function current_user() {
    if (!empty($_SESSION['github_user'])) return $_SESSION['github_user'];

    $h = getallheaders_lower();
    if (!empty($h['authorization']) && preg_match('/Bearer\s+(\S+)/i', $h['authorization'], $m)) {
        $token = $m[1];
        $tokens = db_read('tokens.json') ?: [];
        if (!empty($tokens[$token]) && !empty($tokens[$token]['username'])) {
            if (isset($tokens[$token]['expires_at']) && strtotime($tokens[$token]['expires_at']) < time()) return null;
            return $tokens[$token]['username'];
        }
    }
    return null;
}

function is_admin() {
    global $ADMIN_USERS;
    $u = current_user();
    return $u && in_array($u, $ADMIN_USERS);
}

function require_auth() {
    $u = current_user();
    if (!$u) { json_response(['error' => 'Unauthorized', 'payload' => null], 401); return false; }
    return true;
}

function require_admin() {
    if (!is_admin()) { json_response(['error' => 'Forbidden - Admin only', 'payload' => null], 403); return false; }
    return true;
}

function getallheaders_lower() {
    if (!function_exists('getallheaders')) {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
                $headers[$name] = $value;
            }
        }
        $out = [];
        foreach ($headers as $k => $v) $out[strtolower($k)] = $v;
        return $out;
    }
    $h = [];
    foreach (getallheaders() as $k => $v) $h[strtolower($k)] = $v;
    return $h;
}

function normalize_version($v) {
    if ($v === null) return null;
    $s = trim((string)$v);
    if ($s === '') return null;
    return preg_replace('/^v/i', '', $s);
}

function normalize_geode($g) {
    if ($g === null) return null;
    $s = trim((string)$g);
    return $s === '' ? null : $s;
}

function normalize_gd($gd) {
    if (empty($gd) || !is_array($gd)) return null;
    $out = [];
    foreach ($gd as $k => $val) {
        if ($val === null) continue;
        $s = (string)$val;
        if ($s === '') continue;
        $out[$k] = $s;
    }
    return empty($out) ? null : expand_gd_platforms($out);
}

function default_developer_role($is_owner) {
    return $is_owner ? 'Owner' : 'Developer';
}

function map_modjson_developers($devs, $submitter = null) {
    $out = [];
    if (empty($devs)) {
        if ($submitter) $out[] = ['id' => null, 'username' => $submitter, 'display_name' => $submitter, 'is_owner' => true, 'role' => 'Owner'];
        return $out;
    }
    foreach ($devs as $d) {
        if (is_string($d)) {
            $out[] = ['id' => null, 'username' => $d, 'display_name' => $d, 'is_owner' => false, 'role' => 'Developer'];
        } elseif (is_array($d)) {
            $username = $d['username'] ?? ($d['name'] ?? null);
            $display  = $d['display_name'] ?? ($username ?: '');
            $is_owner = !empty($d['is_owner']);
            $role     = !empty($d['role']) ? (string)$d['role'] : default_developer_role($is_owner);
            $out[] = ['id' => $d['id'] ?? null, 'username' => $username, 'display_name' => $display, 'is_owner' => $is_owner, 'role' => $role];
        }
    }
    if ($submitter) {
        $found = false;
        foreach ($out as &$o) {
            if ($o['username'] === $submitter) {
                $o['is_owner'] = true;
                if (empty($o['role']) || $o['role'] === 'Developer') $o['role'] = 'Owner';
                $found = true;
                break;
            }
        }
        unset($o);
        if (!$found) $out[] = ['id' => null, 'username' => $submitter, 'display_name' => $submitter, 'is_owner' => true, 'role' => 'Owner'];
    }
    return $out;
}

/* ======================= GITHUB helpers & token issuance ======================= */

function github_exchange_code($code) {
    if (!defined('CLIENT_ID') || CLIENT_ID === '') return null;

    $post = http_build_query([
        'client_id'     => CLIENT_ID,
        'client_secret' => CLIENT_SECRET,
        'code'          => $code,
        'redirect_uri'  => CALLBACK_URL ?: current_url_base() . '/callback',
    ]);
    $opts = [
        'http' => [
            'method'  => 'POST',
            'header'  => "Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " . strlen($post) . "\r\n",
            'content' => $post,
            'timeout' => 10,
        ],
    ];
    $res = @file_get_contents('https://github.com/login/oauth/access_token', false, stream_context_create($opts));
    if ($res === false) return null;
    $json = json_decode($res, true);
    return $json['access_token'] ?? null;
}

function github_get_user($token) {
    $opts = ['http' => [
        'method'  => 'GET',
        'header'  => "User-Agent: Open-Geode-Index\r\nAuthorization: token " . $token . "\r\nAccept: application/json\r\n",
        'timeout' => 10,
    ]];
    $res = @file_get_contents('https://api.github.com/user', false, stream_context_create($opts));
    if ($res === false) return null;
    return json_decode($res, true);
}

function issue_local_tokens_for_user($username) {
    $tokens = db_read('tokens.json') ?: [];
    $access = bin2hex(random_bytes(20));
    $refresh = bin2hex(random_bytes(24));
    $now = time();
    $tokens[$access] = [
        'username'           => $username,
        'issued_at'          => iso8601_utc($now),
        'expires_at'         => iso8601_utc($now + ACCESS_TOKEN_TTL),
        'refresh_token'      => $refresh,
        'refresh_expires_at' => iso8601_utc($now + REFRESH_TOKEN_TTL),
    ];
    db_write('tokens.json', $tokens);
    return ['access_token' => $access, 'refresh_token' => $refresh];
}

function ensure_developer_record($username, $display = null) {
    $devs = db_read('developers.json') ?: [];
    foreach ($devs as $d) if (($d['username'] ?? null) === $username) return;
    $devs[] = ['id' => time(), 'username' => $username, 'display_name' => $display ?: $username, 'verified' => false, 'admin' => false, 'github_id' => null];
    db_write('developers.json', $devs);
}

function current_url_base() {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    return $scheme . '://' . $_SERVER['HTTP_HOST'];
}

function expand_gd_platforms($gd) {
    if (empty($gd) || !is_array($gd)) return $gd;
    $out = $gd;
    if (isset($gd['android']) && $gd['android'] !== null && $gd['android'] !== '') {
        if (!isset($out['android32'])) $out['android32'] = $gd['android'];
        if (!isset($out['android64'])) $out['android64'] = $gd['android'];
    }
    if (isset($gd['mac']) && $gd['mac'] !== null && $gd['mac'] !== '') {
        if (!isset($out['mac-intel'])) $out['mac-intel'] = $gd['mac'];
        if (!isset($out['mac-arm']))   $out['mac-arm']   = $gd['mac'];
    }
    return $out;
}

function public_download_link($modid, $version) {
    return rtrim(current_url_base(), '/') . '/v1/mods/' . rawurlencode($modid) . '/versions/' . rawurlencode($version) . '/download';
}

function version_for_public($modid, $v) {
    $out = $v;
    if (isset($out['gd'])) $out['gd'] = expand_gd_platforms($out['gd']);

    if (!empty($v['download_link'])) {
        $out['download_link'] = public_download_link($modid, $v['version']);
        return $out;
    }

    $up = fetch_upstream_json("/v1/mods/{$modid}");
    if ($up && !empty($up['payload'])) {
        $upmod = $up['payload'];
        if (!empty($upmod['versions']) && is_array($upmod['versions'])) {
            foreach ($upmod['versions'] as $uv) {
                if ((isset($uv['version']) && $uv['version'] === ($v['version'] ?? null)) || empty($v['version'])) {
                    if (!empty($uv['download_link'])) { $out['download_link'] = $uv['download_link']; break; }
                }
            }
        }
    }
    if (empty($out['download_link'])) $out['download_link'] = '';
    return $out;
}

function mod_for_public($mod) {
    if (empty($mod) || !isset($mod['id'])) return $mod;
    $out = $mod;
    if (!empty($out['versions']) && is_array($out['versions'])) {
        $arr = [];
        foreach ($out['versions'] as $v) $arr[] = version_for_public($out['id'], $v);
        $out['versions'] = $arr;
    }
    return $out;
}

// [PATCH] Кэш upstream на 5 минут (кроме override через X-Upstream-Url)
function fetch_upstream_json($path, $query = [], $ttl = UPSTREAM_CACHE_TTL) {
    $base = defined('UPSTREAM_URL') ? UPSTREAM_URL : 'https://api.geode-sdk.org';
    $url = $base . '/' . ltrim($path, '/');

    $hdrs = getallheaders_lower();
    $override = !empty($hdrs['x-upstream-url']) && stripos($hdrs['x-upstream-url'], 'http') === 0;
    if ($override) $url = $hdrs['x-upstream-url'];

    if (!empty($query)) $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($query);

    $cache_dir = DATA_DIR . '/cache';
    $use_cache = $ttl > 0 && !$override;
    $cache_file = $cache_dir . '/' . md5($url) . '.json';

    if ($use_cache && file_exists($cache_file) && (time() - filemtime($cache_file)) < $ttl) {
        $cached = @file_get_contents($cache_file);
        if ($cached !== false) { $j = json_decode($cached, true); if ($j !== null) return $j; }
    }

    $opts = ['http' => ['method' => 'GET', 'header' => "User-Agent: Open-Geode-Index\r\nAccept: application/json\r\n", 'timeout' => 22]];
    $res = @file_get_contents($url, false, stream_context_create($opts));
    if ($res === false) return null;

    $j = json_decode($res, true);
    if ($j === null) return null;

    if ($use_cache) {
        if (!is_dir($cache_dir)) @mkdir($cache_dir, 0755, true);
        @file_put_contents($cache_file, $res, LOCK_EX);
    }
    return $j;
}

function resolve_final_url($url, $max_redirects = 8, $timeout = 8) {
    if (empty($url)) return ['url' => null, 'code' => null];
    if (!is_safe_url($url)) return ['url' => null, 'code' => null];

    $current = $url;
    $redirects = 0;
    $ctx = stream_context_create(['http' => [
        'method' => 'GET',
        'header' => "User-Agent: Open-Geode-Index\r\nAccept: */*\r\n",
        'timeout' => $timeout,
        'ignore_errors' => true,
    ]]);

    while ($redirects <= $max_redirects) {
        $headers = @get_headers($current, 1, $ctx);
        if ($headers === false) return ['url' => null, 'code' => null];

        $statusLine = isset($headers[0]) ? (is_array($headers[0]) ? end($headers[0]) : $headers[0]) : null;
        $code = null;
        if ($statusLine && preg_match('/HTTP\/[\d\.]+\s+([0-9]{3})/i', $statusLine, $m)) $code = intval($m[1]);

        if ($code !== null && $code >= 300 && $code < 400 && !empty($headers['Location'])) {
            $loc = $headers['Location'];
            if (is_array($loc)) $loc = end($loc);
            if (parse_url($loc, PHP_URL_SCHEME) === null) {
                $base = parse_url($current);
                $scheme = $base['scheme'] ?? 'https';
                $host = $base['host'] ?? '';
                $port = isset($base['port']) ? ':' . $base['port'] : '';
                if (strpos($loc, '/') === 0) $loc = $scheme . '://' . $host . $port . $loc;
                else $loc = $scheme . '://' . $host . $port . (isset($base['path']) ? dirname($base['path']) . '/' : '') . $loc;
            }
            if (!is_safe_url($loc)) return ['url' => null, 'code' => null];
            $current = $loc;
            $redirects++;
            continue;
        }
        return ['url' => $current, 'code' => $code];
    }
    return ['url' => null, 'code' => null];
}

function iso8601_utc($ts = null) {
    if ($ts === null) $ts = time();
    return gmdate('Y-m-d\TH:i:s\Z', (int)$ts);
}

function fetch_github_raw_json($repo, $path) {
    $url = "https://raw.githubusercontent.com/{$repo}/HEAD/{$path}";
    $opts = ['http' => ['method' => 'GET', 'header' => "User-Agent: Open-Geode-Index\r\nAccept: application/json\r\n", 'timeout' => 8]];
    $res = @file_get_contents($url, false, stream_context_create($opts));
    if ($res === false) return null;
    return json_decode($res, true) ?: null;
}

function fetch_github_raw_text($repo, $path) {
    $url = "https://raw.githubusercontent.com/{$repo}/HEAD/{$path}";
    $opts = ['http' => ['method' => 'GET', 'header' => "User-Agent: Open-Geode-Index\r\nAccept: text/plain\r\n", 'timeout' => 8]];
    $res = @file_get_contents($url, false, stream_context_create($opts));
    return $res === false ? null : $res;
}

/* ======================= API: tags ======================= */

function api_tags_index() {
    $tags = db_read('tags.json') ?: [];
    $names = [];
    foreach ($tags as $t) $names[] = is_array($t) && isset($t['name']) ? $t['name'] : (string)$t;
    json_response_etag(['error' => '', 'payload' => $names], 200, 300);
}

function api_tags_detailed() {
    $tags = db_read('tags.json') ?: [];
    json_response_etag(['error' => '', 'payload' => $tags], 200, 300);
}

/* ======================= API: developers ======================= */

function api_developers_index() {
    $q = $_GET;
    $devs = db_read('developers.json') ?: [];

    if (!empty($q['query'])) {
        $qq = strtolower($q['query']);
        $devs = array_values(array_filter($devs, function ($d) use ($qq) {
            return (strpos(strtolower($d['username']), $qq) !== false) || (strpos(strtolower($d['display_name']), $qq) !== false);
        }));
    }

    $page = isset($q['page']) ? max(1, intval($q['page'])) : 1;
    $per_page = isset($q['per_page']) ? max(1, min(200, intval($q['per_page']))) : 50;
    $count = count($devs);
    $data = array_slice($devs, ($page - 1) * $per_page, $per_page);
    json_response(['error' => '', 'payload' => ['data' => $data, 'count' => $count]]);
}

function api_developers_get($id) {
    $devs = db_read('developers.json') ?: [];
    foreach ($devs as $d) if (intval($d['id']) === $id) return json_response(['error' => '', 'payload' => $d]);
    json_response(['error' => 'Developer not found', 'payload' => null], 404);
}

function api_developers_update($id) {
    if (!require_admin()) return;
    $body = json_input();
    if (!$body) return json_response(['error' => 'bad request', 'payload' => null], 400);

    $devs = db_read('developers.json') ?: [];
    foreach ($devs as $i => $d) {
        if (intval($d['id']) === $id) {
            if (isset($body['admin']))    $devs[$i]['admin'] = (bool)$body['admin'];
            if (isset($body['verified'])) $devs[$i]['verified'] = (bool)$body['verified'];
            db_write('developers.json', $devs);
            api_log('developer.update', ['id' => $id]);
            return json_response(['error' => '', 'payload' => $devs[$i]]);
        }
    }
    json_response(['error' => 'Developer not found', 'payload' => null], 404);
}

/* ======================= API: auth ======================= */

function api_login_github() {
    $state = bin2hex(random_bytes(12));
    $_SESSION['oauth_state'] = $state;
    $redirect = CALLBACK_URL ?: current_url_base() . '/callback';
    $params = http_build_query(['client_id' => CLIENT_ID, 'redirect_uri' => $redirect, 'scope' => 'read:user', 'state' => $state]);
    json_response(['error' => '', 'payload' => "https://github.com/login/oauth/authorize?$params"]);
}

function api_login_github_web() { return api_login_github(); }

function api_login_callback() {
    $body = json_input() ?: $_REQUEST;
    if (empty($body['code']) || empty($body['state'])) return json_response(['error' => 'bad request', 'payload' => null], 400);

    if (!isset($_SESSION['oauth_state']) || $_SESSION['oauth_state'] !== $body['state']) {
        return json_response(['error' => 'invalid state', 'payload' => null], 400);
    }
    $token = github_exchange_code($body['code']);
    if (!$token) return json_response(['error' => 'failed to obtain access token', 'payload' => null], 400);

    $user = github_get_user($token);
    if (!$user || empty($user['login'])) return json_response(['error' => 'failed to fetch GitHub user', 'payload' => null], 400);

    $_SESSION['github_user'] = $user['login'];
    $_SESSION['github_token'] = $token;
    ensure_developer_record($user['login'], $user['name'] ?? $user['login']);
    $local = issue_local_tokens_for_user($user['login']);
    api_log('login.callback', ['user' => $user['login']]);
    json_response(['error' => '', 'payload' => $local]);
}

function api_login_github_poll() {
    json_response(['error' => 'not implemented', 'payload' => null], 501);
}

function api_login_github_token() {
    $body = json_input();
    if (!$body || empty($body['token'])) return json_response(['error' => 'bad request', 'payload' => null], 400);

    $user = github_get_user($body['token']);
    if (!$user || empty($user['login'])) return json_response(['error' => 'invalid access token', 'payload' => null], 400);

    ensure_developer_record($user['login'], $user['name'] ?? $user['login']);
    $local = issue_local_tokens_for_user($user['login']);
    json_response(['error' => '', 'payload' => $local]);
}

function api_refresh_token() {
    $body = json_input();
    if (!$body || empty($body['refresh_token'])) return json_response(['error' => 'bad request', 'payload' => null], 400);

    $refresh = $body['refresh_token'];
    $tokens = db_read('tokens.json') ?: [];
    foreach ($tokens as $at => $meta) {
        if (!empty($meta['refresh_token']) && $meta['refresh_token'] === $refresh) {
            if (isset($meta['refresh_expires_at']) && strtotime($meta['refresh_expires_at']) < time()) {
                return json_response(['error' => 'invalid or expired refresh token', 'payload' => null], 400);
            }
            $new = issue_local_tokens_for_user($meta['username']);
            return json_response(['error' => '', 'payload' => $new]);
        }
    }
    json_response(['error' => 'invalid or expired refresh token', 'payload' => null], 400);
}

/* ======================= API: me ======================= */

function api_get_me() {
    if (!require_auth()) return;
    $u = current_user();
    $devs = db_read('developers.json') ?: [];
    foreach ($devs as $d) if (($d['username'] ?? null) === $u) return json_response(['error' => '', 'payload' => $d]);
    json_response(['error' => '', 'payload' => ['id' => null, 'username' => $u, 'display_name' => $u, 'verified' => false, 'admin' => is_admin(), 'github_id' => null]]);
}

function api_put_me() {
    if (!require_auth()) return;
    $u = current_user();
    $body = json_input();
    if (!$body) return json_response(['error' => 'bad request', 'payload' => null], 400);

    $devs = db_read('developers.json') ?: [];
    foreach ($devs as $i => $d) {
        if (($d['username'] ?? null) === $u) {
            if (isset($body['display_name'])) $devs[$i]['display_name'] = $body['display_name'];
            db_write('developers.json', $devs);
            return json_response(['error' => '', 'payload' => $devs[$i]]);
        }
    }

    $new = ['id' => time(), 'username' => $u, 'display_name' => $body['display_name'] ?? $u, 'verified' => false, 'admin' => false, 'github_id' => null];
    $devs[] = $new;
    db_write('developers.json', $devs);
    json_response(['error' => '', 'payload' => $new]);
}

function api_get_own_mods() {
    if (!require_auth()) return;
    $u = current_user();
    $mods = db_read('mods.json') ?: [];
    $own = array_values(array_filter($mods, function ($m) use ($u) {
        if (!empty($m['developers']) && is_array($m['developers'])) {
            foreach ($m['developers'] as $d) if (!empty($d['username']) && $d['username'] === $u) return true;
        }
        return false;
    }));
    json_response(['error' => '', 'payload' => $own]);
}

function api_delete_token() {
    if (!require_auth()) return;
    $h = getallheaders_lower();
    if (!empty($h['authorization']) && preg_match('/Bearer\s+(\S+)/i', $h['authorization'], $m)) {
        $tokens = db_read('tokens.json') ?: [];
        if (isset($tokens[$m[1]])) {
            unset($tokens[$m[1]]);
            db_write('tokens.json', $tokens);
            return json_response(['error' => '', 'payload' => null], 204);
        }
        return json_response(['error' => 'not found', 'payload' => null], 404);
    }
    json_response(['error' => '', 'payload' => null], 204);
}

function api_delete_tokens() {
    if (!require_auth()) return;
    $u = current_user();
    $tokens = db_read('tokens.json') ?: [];
    foreach ($tokens as $k => $meta) if (($meta['username'] ?? null) === $u) unset($tokens[$k]);
    db_write('tokens.json', $tokens);
    json_response(['error' => '', 'payload' => null], 204);
}

/* ======================= API: loader versions ======================= */

function api_loader_versions_index() {
    $q = $_GET;
    $all = db_read('loader_versions.json') ?: [];

    if (isset($q['prerelease'])) {
        $pr = filter_var($q['prerelease'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($pr !== null) $all = array_values(array_filter($all, fn($v) => !empty($v['prerelease']) === $pr));
    }
    if (!empty($q['gd'])) {
        $gd = (string)$q['gd'];
        $all = array_values(array_filter($all, fn($v) => !empty($v['gd']) && (is_string($v['gd']) ? strpos($v['gd'], $gd) !== false : true)));
    }

    $page = isset($q['page']) ? max(1, intval($q['page'])) : 1;
    $per_page = isset($q['per_page']) ? max(1, min(200, intval($q['per_page']))) : 50;
    $count = count($all);
    json_response(['error' => '', 'payload' => ['data' => array_slice($all, ($page - 1) * $per_page, $per_page), 'count' => $count]]);
}

function api_loader_versions_create() {
    if (!require_admin()) return;
    $body = json_input();
    if (!$body || empty($body['tag']) || empty($body['commit_hash']) || empty($body['gd'])) {
        return json_response(['error' => 'bad request', 'payload' => null], 400);
    }

    $all = db_read('loader_versions.json') ?: [];
    $v = [
        'version'     => $body['tag'],
        'tag'         => $body['tag'],
        'gd'          => $body['gd'],
        'prerelease'  => !empty($body['prerelease']),
        'commit_hash' => $body['commit_hash'],
        'created_at'  => iso8601_utc(),
    ];
    array_unshift($all, $v);
    db_write('loader_versions.json', $all);
    api_log('loader.create', ['tag' => $body['tag']]);
    json_response(['error' => '', 'payload' => $v], 201);
}

function api_loader_versions_get($version) {
    $all = db_read('loader_versions.json') ?: [];
    foreach ($all as $v) if ($v['version'] === $version || $v['tag'] === $version) return json_response(['error' => '', 'payload' => $v]);
    json_response(['error' => 'not found', 'payload' => null], 404);
}

/* ======================= API: mods ======================= */

function api_mods_index() {
    $q = $_GET;
    $mods = db_read('mods.json') ?: [];

    if (!empty($q['query'])) {
        $qq = mb_strtolower($q['query']);
        $mods = array_values(array_filter($mods, function ($m) use ($qq) {
            $hay = mb_strtolower(implode(' ', array_filter([$m['id'] ?? '', $m['about'] ?? '', implode(' ', $m['tags'] ?? [])])));
            return mb_strpos($hay, $qq) !== false;
        }));
    }
    if (!empty($q['tags'])) {
        $wanted = array_map('trim', explode(',', $q['tags']));
        $mods = array_values(array_filter($mods, function ($m) use ($wanted) {
            $tags = $m['tags'] ?? [];
            foreach ($wanted as $t) if (!in_array($t, $tags)) return false;
            return true;
        }));
    }
    if (isset($q['featured'])) {
        $f = filter_var($q['featured'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($f !== null) $mods = array_values(array_filter($mods, fn($m) => !empty($m['featured']) === $f));
    }

    $sort = isset($q['sort']) ? (string)$q['sort'] : 'downloads';
    $ts = function ($d) { if (empty($d)) return 0; $t = @strtotime($d); return $t === false ? 0 : $t; };
    $tiebreak = function ($x, $y) use ($ts) {
        $ux = $ts($x['updated_at'] ?? null);
        $uy = $ts($y['updated_at'] ?? null);
        if ($ux !== $uy) return $uy <=> $ux;
        return strtolower($x['id'] ?? '') <=> strtolower($y['id'] ?? '');
    };

    usort($mods, function ($a, $b) use ($sort, $ts, $tiebreak) {
        switch ($sort) {
            case 'recently_updated':
                $a_t = $ts($a['updated_at'] ?? null); $b_t = $ts($b['updated_at'] ?? null);
                return $a_t === $b_t ? $tiebreak($a, $b) : $b_t <=> $a_t;
            case 'recently_published':
                $a_t = $ts($a['created_at'] ?? null); $b_t = $ts($b['created_at'] ?? null);
                return $a_t === $b_t ? $tiebreak($a, $b) : $b_t <=> $a_t;
            case 'oldest':
                $a_t = $ts($a['created_at'] ?? null); $b_t = $ts($b['created_at'] ?? null);
                return $a_t === $b_t ? $tiebreak($a, $b) : $a_t <=> $b_t;
            case 'name':
                $na = strtolower($a['id'] ?? ''); $nb = strtolower($b['id'] ?? '');
                return $na === $nb ? $tiebreak($a, $b) : $na <=> $nb;
            case 'name_reverse':
                $na = strtolower($a['id'] ?? ''); $nb = strtolower($b['id'] ?? '');
                return $na === $nb ? $tiebreak($a, $b) : $nb <=> $na;
            case 'downloads':
            default:
                $da = (int)($a['download_count'] ?? 0); $db = (int)($b['download_count'] ?? 0);
                return $da === $db ? $tiebreak($a, $b) : $db <=> $da;
        }
    });

    $page = isset($q['page']) ? max(1, intval($q['page'])) : 1;
    $per_page = isset($q['per_page']) ? max(1, min(200, intval($q['per_page']))) : 50;
    $count = count($mods);
    $slice = array_slice($mods, ($page - 1) * $per_page, $per_page);

    $public = [];
    foreach ($slice as $m) $public[] = mod_for_public($m);

    json_response(['error' => '', 'payload' => ['data' => $public, 'count' => $count]]);
}

function api_mods_create() {
    if (!require_auth()) return;
    $u = current_user();

    $body = json_input();
    if (!$body) return json_response(['error' => 'bad request - empty body', 'payload' => null], 400);
    if (empty($body['download_link'])) return json_response(['error' => 'bad request - download_link required', 'payload' => null], 400);

    $repo = !empty($body['repo']) ? trim($body['repo']) : null;

    $meta = extract_metadata_from_geode($body['download_link']);
    if ($meta === null || empty($meta['modjson'])) {
        return json_response(['error' => 'bad request - mod.json not found inside .geode (metadata must come from archive)', 'payload' => null], 400);
    }
    $modjson = $meta['modjson'];

    $mod_id = !empty($modjson['id']) ? (string)$modjson['id'] : ($repo ?: null);
    if (empty($mod_id)) return json_response(['error' => 'bad request - cannot determine mod id', 'payload' => null], 400);

    $mod_name = !empty($modjson['name']) ? (string)$modjson['name'] : $mod_id;
    $mod_tags = !empty($modjson['tags']) && is_array($modjson['tags']) ? $modjson['tags'] : [];
    $mod_about = $meta['about'] ?? null;
    $changelog = $meta['changelog'] ?? null;

    $initial_version = normalize_version($body['version'] ?? ($modjson['version'] ?? null)) ?: '1.0.0';

    $featured = false;
    if (!empty($body['featured']) && is_admin()) $featured = (bool)$body['featured'];

    $geode_val = isset($modjson['geode']) ? normalize_geode($modjson['geode']) : null;
    $gd_val = isset($modjson['gd']) && is_array($modjson['gd']) ? normalize_gd($modjson['gd']) : null;

    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $m) if (($m['id'] ?? null) === $mod_id) return json_response(['error' => 'mod already exists (by id)', 'payload' => null], 409);

    $hash_val = compute_remote_sha256($body['download_link']);
    if ($hash_val === null) return json_response(['error' => 'bad request - can\'t get sha256 from download_link', 'payload' => null], 400);

    $now = iso8601_utc();
    $version_entry = [
        'name' => $mod_name, 'version' => $initial_version, 'download_link' => $body['download_link'],
        'hash' => $hash_val, 'geode' => $geode_val, 'download_count' => 0,
        'early_load' => !empty($body['early_load']), 'requires_patching' => !empty($body['requires_patching']),
        'api' => !empty($body['api']), 'mod_id' => $mod_id, 'gd' => expand_gd_platforms($gd_val),
        'status' => 'accepted', 'description' => $modjson['description'] ?? null,
        'created_at' => $now, 'updated_at' => $now,
    ];

    $repository_url = $repo ? "https://github.com/{$repo}" : null;
    $logo_url = !empty($modjson['logo_url']) ? $modjson['logo_url'] : ($repo ? "https://raw.githubusercontent.com/{$repo}/HEAD/logo.png" : null);

    $devs = !empty($modjson['developers'])
        ? map_modjson_developers($modjson['developers'], $u)
        : map_modjson_developers([], $u);

    $mod = [
        'id' => $mod_id, 'about' => $mod_about, 'changelog' => $changelog,
        'created_at' => $now, 'updated_at' => $now, 'developers' => $devs,
        'download_count' => 0, 'featured' => $featured, 'tags' => $mod_tags,
        'versions' => [$version_entry], 'repo' => $repo, 'repository' => $repository_url,
        'logo_url' => $logo_url,
        'links' => isset($modjson['links']) && is_array($modjson['links']) ? $modjson['links'] : null,
        'submitted_by' => $u,
    ];

    $mods[] = $mod;
    db_write('mods.json', $mods);
    api_log('mod.create', ['id' => $mod_id, 'version' => $initial_version]);
    json_response(['error' => '', 'payload' => mod_for_public($mod)], 201);
}

function api_mods_get($id) {
    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $m) {
        if ($m['id'] !== $id) continue;

        if ((empty($m['about']) || !empty($m['prefer_github_info'])) && !empty($m['repo'])) {
            $text = fetch_github_raw_text($m['repo'], 'about.md');
            if ($text === null) $text = fetch_github_raw_text($m['repo'], 'README.md');
            if ($text !== null) $m['about'] = $text;
        }
        if ((empty($m['changelog']) || !empty($m['prefer_github_info'])) && !empty($m['repo'])) {
            $text = fetch_github_raw_text($m['repo'], 'changelog.md');
            if ($text === null) $text = fetch_github_raw_text($m['repo'], 'CHANGELOG.md');
            if ($text !== null) $m['changelog'] = $text;
        }
        return json_response(['error' => '', 'payload' => mod_for_public($m)]);
    }

    if (defined('UPSTREAM_URL') && UPSTREAM_URL) {
        $up = fetch_upstream_json("/v1/mods/" . rawurlencode($id));
        if ($up && isset($up['error']) && $up['error'] === '' && !empty($up['payload'])) {
            return json_response(['error' => '', 'payload' => $up['payload']]);
        }
        if ($up === null) return json_response(['error' => 'upstream unavailable', 'payload' => null], 502);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mods_update_admin($id) {
    if (!require_admin()) return;
    $body = json_input();
    if (!$body) return json_response(['error' => 'bad request', 'payload' => null], 400);

    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if ($m['id'] === $id) {
            if (isset($body['featured'])) $mods[$i]['featured'] = (bool)$body['featured'];
            if (isset($body['about']))    $mods[$i]['about'] = $body['about'];
            $mods[$i]['updated_at'] = iso8601_utc();
            db_write('mods.json', $mods);
            return json_response(['error' => '', 'payload' => null], 204);
        }
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

function api_mods_update_owner($id) {
    if (!require_auth()) return;
    $u = current_user();

    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if ($m['id'] !== $id) continue;

        $allowed = is_admin();
        if (!$allowed) {
            foreach ($m['developers'] as $d) if (!empty($d['username']) && $d['username'] === $u && !empty($d['is_owner'])) { $allowed = true; break; }
        }
        if (!$allowed) return json_response(['error' => 'forbidden - only owner or admin can update', 'payload' => null], 403);

        $body = json_input();
        if (!$body) return json_response(['error' => 'bad request - empty body', 'payload' => null], 400);

        if (isset($body['tags'])) {
            if (!is_array($body['tags'])) $body['tags'] = array_values(array_filter(array_map('trim', explode(',', $body['tags']))));
            $mods[$i]['tags'] = $body['tags'];
        }

        if (isset($body['owner_display_name'])) {
            $newname = trim((string)$body['owner_display_name']);
            if ($newname !== '') {
                $updated = false;
                if (!empty($mods[$i]['developers']) && is_array($mods[$i]['developers'])) {
                    foreach ($mods[$i]['developers'] as $di => $dev) {
                        if (!empty($dev['is_owner'])) { $mods[$i]['developers'][$di]['display_name'] = $newname; $updated = true; break; }
                    }
                    if (!$updated && count($mods[$i]['developers']) > 0) {
                        $mods[$i]['developers'][0]['display_name'] = $newname;
                        $updated = true;
                    }
                }
                if ($updated) $mods[$i]['updated_at'] = iso8601_utc();
            }
        }

        if (isset($body['prefer_github_info'])) $mods[$i]['prefer_github_info'] = (bool)$body['prefer_github_info'];
        if (isset($body['about']))     $mods[$i]['about'] = (string)$body['about'];
        if (isset($body['changelog'])) $mods[$i]['changelog'] = (string)$body['changelog'];
        if (isset($body['logo_url']))  $mods[$i]['logo_url'] = trim((string)$body['logo_url']) ?: null;

        if (!empty($body['download_link'])) {
            $meta = extract_metadata_from_geode($body['download_link']);
            if ($meta === null || empty($meta['modjson'])) {
                return json_response(['error' => 'bad request - mod.json not found inside .geode', 'payload' => null], 400);
            }
            $inner = $meta['modjson'];

            if (!empty($inner['id']) && $inner['id'] !== $mods[$i]['id']) {
                return json_response(['error' => 'bad request - mod id inside .geode does not match existing mod id', 'payload' => null], 400);
            }

            $ver = normalize_version($body['version'] ?? ($inner['version'] ?? null)) ?: date('YmdHis');
            $now = iso8601_utc();
            $hash_val = compute_remote_sha256($body['download_link']);
            if ($hash_val === null) return json_response(['error' => 'bad request - can\'t get sha256', 'payload' => null], 400);

            $newver = [
                'name' => $inner['name'] ?? ($body['name'] ?? ($mods[$i]['repo'] ?? $mods[$i]['id'])),
                'version' => $ver, 'download_link' => $body['download_link'], 'hash' => $hash_val,
                'geode' => isset($inner['geode']) ? normalize_geode($inner['geode']) : (isset($body['geode']) ? normalize_geode($body['geode']) : null),
                'download_count' => 0, 'early_load' => !empty($body['early_load']),
                'requires_patching' => !empty($body['requires_patching']),
                'api' => !empty($inner['api']) ? (bool)$inner['api'] : !empty($body['api']),
                'mod_id' => $mods[$i]['id'],
                'gd' => isset($inner['gd']) ? normalize_gd($inner['gd']) : (isset($body['gd']) && is_array($body['gd']) ? normalize_gd($body['gd']) : null),
                'status' => 'accepted',
                'description' => $inner['description'] ?? ($body['description'] ?? (!empty($meta['about']) ? mb_strimwidth($meta['about'], 0, 1000, '...') : null)),
                'created_at' => $now, 'updated_at' => $now,
            ];

            $replaced = false;
            foreach ($mods[$i]['versions'] as $vi => $vv) {
                if ($vv['version'] === $newver['version']) {
                    $newver['download_count'] = $vv['download_count'] ?? 0;
                    $newver['created_at'] = $vv['created_at'] ?? $newver['created_at'];
                    $mods[$i]['versions'][$vi] = $newver;
                    $replaced = true;
                    break;
                }
            }
            if (!$replaced) array_unshift($mods[$i]['versions'], $newver);

            if (!empty($meta['about']))     $mods[$i]['about'] = $meta['about'];
            if (!empty($meta['changelog'])) $mods[$i]['changelog'] = $meta['changelog'];

            $mods[$i]['updated_at'] = iso8601_utc();
            db_write('mods.json', $mods);
            api_log('mod.update.owner', ['id' => $id, 'version' => $ver]);
            return json_response(['error' => '', 'payload' => $mods[$i]], 200);
        }

        if (isset($body['links']) && is_array($body['links'])) $mods[$i]['links'] = $body['links'];

        if (!empty($body['refresh_metadata']) && !empty($mods[$i]['versions'][0]['download_link'])) {
            $meta2 = extract_metadata_from_geode($mods[$i]['versions'][0]['download_link']);
            if ($meta2 !== null) {
                if (!empty($meta2['about']))     $mods[$i]['about'] = $meta2['about'];
                if (!empty($meta2['changelog'])) $mods[$i]['changelog'] = $meta2['changelog'];
            }
        }

        $mods[$i]['updated_at'] = iso8601_utc();
        db_write('mods.json', $mods);
        return json_response(['error' => '', 'payload' => $mods[$i]], 200);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mods_delete($id) {
    if (!require_auth()) return;
    $u = current_user();

    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if ($m['id'] !== $id) continue;

        $allowed = is_admin();
        if (!$allowed) {
            foreach ($m['developers'] as $d) if (!empty($d['username']) && $d['username'] === $u && !empty($d['is_owner'])) { $allowed = true; break; }
        }
        if (!$allowed) return json_response(['error' => 'forbidden - only owner or admin can delete', 'payload' => null], 403);

        array_splice($mods, $i, 1);
        db_write('mods.json', $mods);

        $deprec = db_read('deprecations.json') ?: [];
        $deprec = array_values(array_filter($deprec, fn($d) => !isset($d['mod_id']) || $d['mod_id'] !== $id));
        db_write('deprecations.json', $deprec);

        api_log('mod.delete', ['id' => $id]);
        return json_response(['error' => '', 'payload' => null], 204);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mods_updates() {
    $q = $_GET;
    if (empty($q['ids'])) return json_response(['error' => 'bad request - ids required', 'payload' => null], 400);

    // [PATCH] ограничим размер входного списка
    $raw = (string)$q['ids'];
    if (strlen($raw) > 20000) return json_response(['error' => 'ids too long', 'payload' => null], 400);

    $up = fetch_upstream_json('/v1/mods/updates', $q);
    $up_payload = ['deprecations' => [], 'updates' => []];
    if ($up && isset($up['error']) && $up['error'] === '' && isset($up['payload'])) {
        $up_payload = $up['payload'];
        if (!isset($up_payload['deprecations'])) $up_payload['deprecations'] = [];
        if (!isset($up_payload['updates'])) $up_payload['updates'] = [];
    }

    $ids = array_values(array_filter(array_map('trim', preg_split('/[;,]+/', $raw))));
    $client_geode = isset($q['geode']) ? (string)$q['geode'] : null;
    $client_gd = isset($q['gd']) ? (string)$q['gd'] : null;
    $platform = isset($q['platform']) ? (string)$q['platform'] : ($q['platforms'] ?? null);

    $mods = db_read('mods.json') ?: [];
    $deprec = db_read('deprecations.json') ?: [];

    $mods_index = [];
    foreach ($mods as $m) if (!empty($m['id'])) $mods_index[$m['id']] = $m;

    $local_deprec = array_values(array_filter($deprec, fn($d) => isset($d['mod_id']) && in_array($d['mod_id'], $ids)));

    $local_updates = [];
    foreach ($ids as $id) {
        if (!isset($mods_index[$id])) continue;
        $mod = $mods_index[$id];
        $chosen = null;

        if (!empty($mod['versions']) && is_array($mod['versions'])) {
            foreach ($mod['versions'] as $v) {
                if (!empty($v['status']) && strtolower($v['status']) !== 'accepted') continue;
                $v_geode = isset($v['geode']) ? normalize_geode($v['geode']) : null;
                if ($v_geode !== null && $client_geode !== null && version_compare($v_geode, $client_geode, '>')) continue;

                $v_gd = $v['gd'] ?? null;
                if (!empty($client_gd) && !empty($v_gd) && is_array($v_gd)) {
                    $compatible_gd = true;
                    if ($platform) {
                        if (isset($v_gd[$platform])) {
                            $req = (string)$v_gd[$platform];
                            if ($req !== '*' && $req !== '' && version_compare($req, $client_gd, '>')) $compatible_gd = false;
                        }
                    } else {
                        foreach ($v_gd as $req) {
                            if ($req === '*' || $req === '') continue;
                            if (version_compare((string)$req, $client_gd, '>')) { $compatible_gd = false; break; }
                        }
                    }
                    if (!$compatible_gd) continue;
                }
                $chosen = $v;
                break;
            }
        }
        if ($chosen === null) continue;

        $local_updates[] = [
            'id' => $mod['id'], 'version' => $chosen['version'] ?? '',
            'download_link' => $chosen['download_link'] ?? '',
            'dependencies' => $chosen['dependencies'] ?? [],
            'incompatibilities' => $chosen['incompatibilities'] ?? [],
            'gd' => $chosen['gd'] ?? null, 'replacement' => null,
        ];
    }

    $merged_updates = [];
    foreach ($up_payload['updates'] as $u) $merged_updates[$u['id']] = $u;
    foreach ($local_updates as $lu) $merged_updates[$lu['id']] = $lu;

    $final_updates = [];
    foreach ($up_payload['updates'] as $u) {
        if (isset($merged_updates[$u['id']])) { $final_updates[] = $merged_updates[$u['id']]; unset($merged_updates[$u['id']]); }
    }
    foreach ($merged_updates as $rem) $final_updates[] = $rem;

    $all_deprec = array_merge($up_payload['deprecations'], $local_deprec);
    $seen = [];
    $final_deprec = [];
    foreach ($all_deprec as $d) {
        $key = ($d['mod_id'] ?? '') . '|' . ($d['id'] ?? md5(json_encode($d)));
        if (isset($seen[$key])) continue;
        $seen[$key] = true;
        $final_deprec[] = $d;
    }

    json_response(['error' => '', 'payload' => ['deprecations' => $final_deprec, 'updates' => array_values($final_updates)]], 200);
}

/* ======================= API: deprecations ======================= */

function api_deprecations_index($modid) {
    $deprec = db_read('deprecations.json') ?: [];
    $out = array_values(array_filter($deprec, fn($d) => isset($d['mod_id']) && $d['mod_id'] === $modid));
    json_response(['error' => '', 'payload' => $out]);
}

function api_deprecations_create($modid) {
    if (!require_auth()) return;
    $body = json_input();
    if (!$body || empty($body['by']) || empty($body['reason'])) return json_response(['error' => 'bad request', 'payload' => null], 400);

    $deprec = db_read('deprecations.json') ?: [];
    $row = ['id' => time(), 'mod_id' => $modid, 'by' => $body['by'], 'reason' => $body['reason']];
    $deprec[] = $row;
    db_write('deprecations.json', $deprec);
    json_response(['error' => '', 'payload' => $row], 201);
}

function api_deprecations_clear_all($modid) {
    if (!require_admin()) return;
    $deprec = db_read('deprecations.json') ?: [];
    $deprec = array_values(array_filter($deprec, fn($d) => !isset($d['mod_id']) || $d['mod_id'] !== $modid));
    db_write('deprecations.json', $deprec);
    json_response(['error' => '', 'payload' => null], 204);
}

function api_deprecations_update($modid, $depid) {
    if (!require_admin()) return;
    $body = json_input();
    if (!$body) return json_response(['error' => 'bad request', 'payload' => null], 400);

    $deprec = db_read('deprecations.json') ?: [];
    foreach ($deprec as $i => $d) {
        if ($d['id'] === $depid && $d['mod_id'] === $modid) {
            if (isset($body['by']))     $deprec[$i]['by'] = $body['by'];
            if (isset($body['reason'])) $deprec[$i]['reason'] = $body['reason'];
            db_write('deprecations.json', $deprec);
            return json_response(['error' => '', 'payload' => $deprec[$i]], 200);
        }
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

function api_deprecations_delete($modid, $depid) {
    if (!require_admin()) return;
    $deprec = db_read('deprecations.json') ?: [];
    foreach ($deprec as $i => $d) {
        if ($d['id'] === $depid && $d['mod_id'] === $modid) {
            array_splice($deprec, $i, 1);
            db_write('deprecations.json', $deprec);
            return json_response(['error' => '', 'payload' => null], 204);
        }
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

/* ======================= API: mod developers ======================= */

function api_mod_add_developer($modid) {
    if (!require_auth()) return;
    $body = json_input();
    if (!$body || empty($body['username'])) return json_response(['error' => 'bad request', 'payload' => null], 400);

    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if ($m['id'] !== $modid) continue;

        $u = current_user();
        $allowed = is_admin();
        if (!$allowed) {
            foreach ($m['developers'] as $d) if (!empty($d['username']) && $d['username'] === $u && !empty($d['is_owner'])) { $allowed = true; break; }
        }
        if (!$allowed) return json_response(['error' => 'forbidden', 'payload' => null], 403);

        $username = trim((string)$body['username']);
        $role = !empty($body['role']) ? trim((string)$body['role']) : null;
        $is_owner = isset($body['is_owner']) ? !empty($body['is_owner']) : (strtolower((string)$role) === 'owner');
        if ($role === null) $role = default_developer_role($is_owner);

        $found = false;
        foreach ($mods[$i]['developers'] as $j => $d) {
            if (!empty($d['username']) && $d['username'] === $username) {
                $mods[$i]['developers'][$j]['is_owner'] = $is_owner;
                $mods[$i]['developers'][$j]['role'] = $role;
                $found = true;
                break;
            }
        }
        if (!$found) $mods[$i]['developers'][] = ['id' => null, 'username' => $username, 'display_name' => $username, 'is_owner' => $is_owner, 'role' => $role];

        $mods[$i]['updated_at'] = iso8601_utc();
        db_write('mods.json', $mods);
        return json_response(['error' => '', 'payload' => null], 204);
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

function api_mod_remove_developer($modid, $username) {
    if (!require_auth()) return;
    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if ($m['id'] !== $modid) continue;

        $u = current_user();
        $allowed = is_admin();
        if (!$allowed) {
            foreach ($m['developers'] as $d) if (!empty($d['username']) && $d['username'] === $u && !empty($d['is_owner'])) { $allowed = true; break; }
        }
        if (!$allowed) return json_response(['error' => 'forbidden', 'payload' => null], 403);

        foreach ($mods[$i]['developers'] as $j => $d) {
            if (!empty($d['username']) && $d['username'] === $username) {
                array_splice($mods[$i]['developers'], $j, 1);
                db_write('mods.json', $mods);
                return json_response(['error' => '', 'payload' => null], 204);
            }
        }
        return json_response(['error' => 'developer not found', 'payload' => null], 404);
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

function api_mod_logo($modid) {
    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $m) {
        if ($m['id'] === $modid) {
            if (!empty($m['logo_url'])) { header('Location: ' . $m['logo_url'], true, 302); exit; }
            if (!empty($m['repo'])) { header('Location: https://raw.githubusercontent.com/' . $m['repo'] . '/HEAD/logo.png', true, 302); exit; }
            json_response(['error' => 'not found', 'payload' => null], 404);
        }
    }

    if (defined('UPSTREAM_URL') && UPSTREAM_URL) {
        $url = UPSTREAM_URL . '/v1/mods/' . rawurlencode($modid) . '/logo';
        $hdrs = getallheaders_lower();
        if (!empty($hdrs['x-upstream-url']) && stripos($hdrs['x-upstream-url'], 'http') === 0) $url = $hdrs['x-upstream-url'];
        if (@file_get_contents($url)) { header('Location: ' . $url); exit; }
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

/* ======================= API: versions ======================= */

function api_mod_versions_index($modid) {
    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $m) {
        if ($m['id'] === $modid) {
            $out = [];
            foreach ($m['versions'] as $v) $out[] = version_for_public($m['id'], $v);
            return json_response(['error' => '', 'payload' => $out]);
        }
    }

    if (defined('UPSTREAM_URL') && UPSTREAM_URL) {
        $up = fetch_upstream_json("/v1/mods/" . rawurlencode($modid) . "/versions");
        if ($up && isset($up['error']) && $up['error'] === '' && !empty($up['payload'])) {
            return json_response(['error' => '', 'payload' => $up['payload']]);
        }
        if ($up === null) return json_response(['error' => 'upstream unavailable', 'payload' => null], 502);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mod_versions_create($modid) {
    if (!require_auth()) return;
    $body = json_input();
    if (!$body || empty($body['version']) || empty($body['download_link'])) return json_response(['error' => 'bad request', 'payload' => null], 400);

    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if ($m['id'] !== $modid) continue;

        $u = current_user();
        $allowed = is_admin();
        if (!$allowed) {
            foreach ($m['developers'] as $d) if (!empty($d['username']) && $d['username'] === $u && !empty($d['is_owner'])) { $allowed = true; break; }
        }
        if (!$allowed) return json_response(['error' => 'forbidden', 'payload' => null], 403);

        $meta = extract_metadata_from_geode($body['download_link']);
        if ($meta === null || empty($meta['modjson'])) return json_response(['error' => 'bad request - mod.json not found inside .geode', 'payload' => null], 400);
        $inner = $meta['modjson'];
        if (!empty($inner['id']) && $inner['id'] !== $modid) {
            return json_response(['error' => 'bad request - mod id inside .geode does not match mod id', 'payload' => null], 400);
        }

        $ver = normalize_version($body['version']) ?: $body['version'];
        $now = iso8601_utc();
        $hash_val = compute_remote_sha256($body['download_link']);
        if ($hash_val === null) return json_response(['error' => 'bad request - can\'t get sha256', 'payload' => null], 400);

        $newver = [
            'name' => $inner['name'] ?? ($body['name'] ?? $modid),
            'version' => $ver, 'download_link' => $body['download_link'], 'hash' => $hash_val,
            'geode' => isset($inner['geode']) ? normalize_geode($inner['geode']) : (isset($body['geode']) ? normalize_geode($body['geode']) : null),
            'download_count' => 0, 'early_load' => !empty($body['early_load']),
            'requires_patching' => !empty($body['requires_patching']),
            'api' => !empty($inner['api']) ? (bool)$inner['api'] : !empty($body['api']),
            'mod_id' => $m['id'],
            'gd' => isset($inner['gd']) ? normalize_gd($inner['gd']) : (isset($body['gd']) && is_array($body['gd']) ? normalize_gd($body['gd']) : null),
            'status' => 'accepted',
            'description' => $inner['description'] ?? (!empty($meta['about']) ? mb_strimwidth($meta['about'], 0, 1000, '...') : null),
            'created_at' => $now, 'updated_at' => $now,
        ];

        array_unshift($mods[$i]['versions'], $newver);
        if (!empty($meta['about']))     $mods[$i]['about'] = $meta['about'];
        if (!empty($meta['changelog'])) $mods[$i]['changelog'] = $meta['changelog'];
        $mods[$i]['updated_at'] = iso8601_utc();
        db_write('mods.json', $mods);

        return json_response(['error' => '', 'payload' => version_for_public($mods[$i]['id'], $newver)], 201);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mod_versions_get($modid, $version) {
    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $m) {
        if ($m['id'] === $modid) {
            foreach ($m['versions'] as $v) if ($v['version'] === $version) return json_response(['error' => '', 'payload' => version_for_public($m['id'], $v)]);
            return json_response(['error' => 'version not found', 'payload' => null], 404);
        }
    }

    if (defined('UPSTREAM_URL') && UPSTREAM_URL) {
        $up = fetch_upstream_json("/v1/mods/" . rawurlencode($modid) . "/versions/" . rawurlencode($version));
        if ($up && isset($up['error']) && $up['error'] === '' && !empty($up['payload'])) {
            return json_response(['error' => '', 'payload' => $up['payload']]);
        }
        if ($up === null) return json_response(['error' => 'upstream unavailable', 'payload' => null], 502);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mod_versions_update($modid, $version) {
    if (!require_admin()) return;
    $body = json_input();
    if (!$body) return json_response(['error' => 'bad request', 'payload' => null], 400);

    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if ($m['id'] !== $modid) continue;

        foreach ($m['versions'] as $j => $v) {
            if ($v['version'] !== $version) continue;
            if (isset($body['status'])) $mods[$i]['versions'][$j]['status'] = $body['status'];
            if (isset($body['info']))   $mods[$i]['versions'][$j]['info'] = $body['info'];
            if (!empty($body['download_link'])) {
                $new_download = trim($body['download_link']);
                $mods[$i]['versions'][$j]['download_link'] = $new_download;
                $mods[$i]['versions'][$j]['hash'] = compute_remote_sha256($new_download);
            }
            $mods[$i]['versions'][$j]['updated_at'] = iso8601_utc();
            $mods[$i]['updated_at'] = iso8601_utc();
            db_write('mods.json', $mods);
            return json_response(['error' => '', 'payload' => $mods[$i]['versions'][$j]], 200);
        }
        return json_response(['error' => 'version not found', 'payload' => null], 404);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mod_versions_download($modid, $version) {
    $mods = db_read('mods.json') ?: [];

    foreach ($mods as $i => $m) {
        if ($m['id'] !== $modid) continue;

        foreach ($m['versions'] as $j => $v) {
            if ($v['version'] !== $version) continue;

            $local_link = !empty($v['download_link']) ? $v['download_link'] : null;

            // Сначала резолвим ссылку, только потом инкрементим счётчик — иначе накрутка.
            if ($local_link) {
                $res = resolve_final_url($local_link);
                if (!empty($res['url']) && $res['code'] !== null && $res['code'] >= 200 && $res['code'] < 400) {
                    $mods[$i]['versions'][$j]['download_count'] = ($mods[$i]['versions'][$j]['download_count'] ?? 0) + 1;
                    $mods[$i]['download_count'] = ($mods[$i]['download_count'] ?? 0) + 1;
                    db_write('mods.json', $mods);
                    header('Location: ' . $res['url'], true, 302);
                    exit;
                }
            }

            $up = fetch_upstream_json("/v1/mods/{$modid}/versions/{$version}");
            if ($up && isset($up['error']) && $up['error'] === '' && !empty($up['payload'])) {
                $uv = $up['payload'];
                $up_link = !empty($uv['download_link']) ? $uv['download_link'] : null;
                if ($up_link) {
                    $res2 = resolve_final_url($up_link);
                    if (!empty($res2['url']) && $res2['code'] !== null && $res2['code'] >= 200 && $res2['code'] < 400) {
                        $mods[$i]['versions'][$j]['download_count'] = ($mods[$i]['versions'][$j]['download_count'] ?? 0) + 1;
                        $mods[$i]['download_count'] = ($mods[$i]['download_count'] ?? 0) + 1;
                        db_write('mods.json', $mods);
                        header('Location: ' . $res2['url'], true, 302);
                        exit;
                    }
                }
            }

            if ($local_link) { header('Location: ' . $local_link, true, 302); exit; }
            return json_response(['error' => 'version download link not available', 'payload' => null], 502);
        }
        return json_response(['error' => 'version not found', 'payload' => null], 404);
    }

    if (defined('UPSTREAM_URL') && UPSTREAM_URL) {
        $url = UPSTREAM_URL . '/v1/mods/' . rawurlencode($modid) . "/versions/" . $version . "/download";
        $hdrs = getallheaders_lower();
        if (!empty($hdrs['x-upstream-url']) && stripos($hdrs['x-upstream-url'], 'http') === 0) $url = $hdrs['x-upstream-url'];
        if (@file_get_contents($url)) { header('Location: ' . $url); exit; }
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

/* ======================= API: stats ======================= */

function api_stats() {
    // stats меняется часто (счётчики), но 30-секундный etag всё равно полезен
    json_response_etag(['error' => '', 'payload' => api_stats_payload()], 200, 30);
}

/* ======================= UI renderers ======================= */

function handle_home() { header('Location: /ui'); exit; }

// [PATCH] теперь шлёт X-CSRF-Token и не пытается перезагружать страницу
// при ошибке, если это не нужно.
function asAPIReqForm($selector = 'form') {
    $selector_json = json_encode($selector);
    $csrf_json = json_encode(CSRF_TOKEN);
    return <<<HTML
<script>
(function(){
const __csrf = $csrf_json;
const f = document.querySelector($selector_json);
if (!f) return;
f.addEventListener('submit', function(e) {
    e.preventDefault();
    let a = this.querySelector('button[type="submit"]') || this.querySelector('button');
    if (a) {
        a.parentElement.classList.add('disabled','placeholder-glow');
        a.parentElement.style.opacity = '0.5';
        a.classList.add('disabled','placeholder');
        a.disabled = true;
    }
    const formData = new FormData(this);
    fetch(this.action, {
        method: this.method,
        body: formData,
        headers: { 'X-CSRF-Token': __csrf }
    })
    .then(async r => {
        let d; try { d = await r.json(); } catch (_) { throw new Error('Invalid JSON'); }
        if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
        return d;
    })
    .then(d => {
        if (d.error && d.error.trim() !== '') {
            alert('Error: ' + d.error);
            if (a) {
                a.parentElement.classList.remove('disabled','placeholder-glow');
                a.parentElement.style.opacity = '1';
                a.classList.remove('disabled','placeholder');
                a.disabled = false;
            }
        } else {
            alert('Request successful :D');
            window.location.reload();
        }
    })
    .catch(err => {
        alert('Error: ' + err.message);
        if (a) {
            a.parentElement.classList.remove('disabled','placeholder-glow');
            a.parentElement.style.opacity = '1';
            a.classList.remove('disabled','placeholder');
            a.disabled = false;
        }
    });
});
})();
</script>
HTML;
}

function ui_header($title = 'Main', $description = SITE_DESCRIPTION, $icon = ICON_URL) {
    $user = current_user();
    $is_admin = is_admin();

    $site_title = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $description = htmlspecialchars($description, ENT_QUOTES, 'UTF-8');
    $current_url = htmlspecialchars(current_url_base() . $_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8');
    ?>
<!doctype html>
<html data-bs-theme="dark" lang="en">
<head>
  <meta charset="utf-8">
  <title><?php echo $site_title; ?></title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="<?php echo $description; ?>">
  <meta name="theme-color" content="#0b0b0b">
  <meta name="robots" content="index,follow">
  <meta name="yandex-verification" content="0cedeb9d864b51a7" />
  <meta name="csrf-token" content="<?=htmlspecialchars(CSRF_TOKEN, ENT_QUOTES)?>">

  <meta property="og:title" content="<?php echo $site_title; ?>">
  <meta property="og:description" content="<?php echo $description; ?>">
  <meta property="og:image" content="<?php echo htmlspecialchars($icon, ENT_QUOTES, 'UTF-8'); ?>">
  <meta property="og:type" content="website">
  <meta property="og:url" content="<?php echo $current_url; ?>">

  <meta name="twitter:card" content="app">
  <meta name="twitter:title" content="<?php echo $site_title; ?>">
  <meta name="twitter:description" content="<?php echo $description; ?>">
  <meta name="twitter:image" content="<?php echo htmlspecialchars($icon, ENT_QUOTES, 'UTF-8'); ?>">

  <link rel="canonical" href="<?php echo $current_url; ?>">
  <link rel="icon" type="image/png" href="<?php echo htmlspecialchars($icon, ENT_QUOTES, 'UTF-8'); ?>">
  <link rel="apple-touch-icon" href="<?php echo htmlspecialchars($icon, ENT_QUOTES, 'UTF-8'); ?>">

  <script type="application/ld+json">
  {
    "@context": "https://schema.org", "@type": "WebSite",
    "name": "Open Geode Index", "url": "<?php echo current_url_base(); ?>",
    "description": "<?php echo addslashes(SITE_DESCRIPTION); ?>",
    "image": "<?php echo htmlspecialchars($icon, ENT_QUOTES, 'UTF-8'); ?>"
  }
  </script>

  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>

  <style>
    html { overflow-y: scroll; }
    body { overflow-wrap: anywhere; }
    .card-pre { white-space:pre-wrap; }
  </style>
</head>
<body style="padding-top: 80px;">
    <h1 class="d-none"><?php echo htmlspecialchars($title, ENT_QUOTES, 'UTF-8'); ?></h1>
    <nav class="navbar fixed-top navbar-expand-lg border-bottom px-4 bg-black">
        <a class="navbar-brand" href="/ui">Open Geode Index</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#mainNavbar" aria-controls="mainNavbar" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="mainNavbar" style="justify-content: space-between;">
            <ul class="navbar-nav nav-underline mr-auto">
                <li class="nav-item"><a class="nav-link <?php if ($title == "Installing Open Geode Index..."): ?>active<?php endif; ?>" href="/install">How to install</a></li>
                <li class="nav-item"><a class="nav-link <?php if ($title == "Users - Open Geode Index"): ?>active<?php endif; ?>" href="/developers">Users</a></li>
                <?php if ($is_admin): ?>
                <li class="nav-item"><a class="nav-link <?php if ($title == "Admin - Open Geode Index"): ?>active<?php endif; ?>" href="/ui/admin">Admin</a></li>
                <?php endif; ?>
            </ul>
            <div class="form-inline my-2 my-lg-0" style="display: flex;align-items: center;">
            <?php if ($user): ?>
                <span class="me-3">Signed in as <b><a <?= $is_admin ? 'class="link-danger"' : '' ?> href="https://github.com/<?=htmlspecialchars($user)?>" target="_blank"><?=htmlspecialchars($user)?></a></b></span>
                <a class="btn btn-outline-danger btn-sm" href="/logout">Logout</a>
            <?php else: ?>
                <a class="btn btn-light btn-sm" href="/login">Sign in with GitHub</a>
            <?php endif; ?>
            </div>
        </div>
    </nav>
    <div class="container py-3 mb-3 border rounded" style="backdrop-filter: brightness(0.7);">
    <?php
}

function ui_footer() {
    ?>
</div>
<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    <?php
}

function render_ui() {
    $stats = api_stats_payload();
    $user = current_user();
    ui_header('Open Geode Index');
    ?>
    <style>
        .highlight-search { background: yellow !important; color: black !important; }
        .skeleton-card { height: 120px; border-radius: 8px; animation: pulse 1.5s ease-in-out infinite; background: var(--bs-secondary-bg); }
        @keyframes pulse { 0%, 100% { opacity: 0.4; } 50% { opacity: 0.8; } }
        .tag-btn { font-size: 0.7rem; padding: 2px 10px; border-radius: 12px; border: 1px solid var(--bs-border-color); background: transparent; color: var(--bs-secondary-color); cursor: pointer; transition: all 0.15s; text-transform: capitalize; }
        .tag-btn:hover { background: var(--bs-secondary-bg); }
        .tag-btn.active { background: var(--bs-primary); color: #fff; border-color: var(--bs-primary); }
        .filter-section { background: rgba(255,255,255,0.03); border-radius: 8px; padding: 12px 16px; }
        .empty-state { text-align: center; padding: 40px 20px; color: var(--bs-secondary-color); }
        .pagination-bar { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-top: 16px; }
        .mod-card { position: relative; }
        .mod-card .downloads-badge { position: absolute; bottom: 3px; right: 5px; font-size: 0.8rem; color: var(--bs-secondary-color); }
        .mod-card .like-btn { position: absolute; right: 3px; top: 5px; }
        .mod-card .tags-row { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 2px; text-transform: capitalize; }
        .mod-card .tags-row .tag-badge { font-size: 0.6rem; padding: 1px 8px; border-radius: 10px; background: var(--bs-secondary-bg); color: var(--bs-secondary-color); }
        .mod-card .mod-title-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    </style>

    <div class="row">
        <div class="col-md-4 my-1 py-1 border-end d-flex flex-column border-2">
            <h3>About project</h3>
            <hr class="my-1 mb-3">
            <p>Welcome to the ALTERNATIVE catalog of mods for Geode, here you can find forbidden or lost mods that are kindly hidden from you. <i>Enjoy the underground~</i></p>
            <p style="display: flex;justify-content: space-evenly;">
                <a class="link-primary link-offset-2 link-underline-opacity-25 link-underline-opacity-100-hover" href="https://discord.gg/kXjQ8QEWNU" target="_blank">Discord</a>
                <a class="link-info link-offset-2 link-underline-opacity-25 link-underline-opacity-100-hover" href="https://t.me/lil2kki_ch" target="_blank">Telegram</a>
                <a class="link-body-emphasis link-offset-2 link-underline-opacity-25 link-underline-opacity-100-hover" href="https://github.com/lil2kki/Open-Geode-Index" target="_blank">GitHub</a>
            </p>
            <dl class="row px-2 mb-1">
                <dt class="col-10 border-start my-1">Total mod count</dt>
                <dd class="col-2 text-end border-end btn btn-link rounded-0 btn-sm fs-5 py-0" id="stat-total-mods"><?=htmlspecialchars($stats['total_mod_count'] ?? 0)?></dd>
                <dt class="col-10 border-start my-1">Total registered users (devs)</dt>
                <dd class="col-2 text-end border-end btn btn-link rounded-0 btn-sm fs-5 py-0"><?=htmlspecialchars($stats['total_registered_developers'] ?? 0)?></dd>
            </dl>
            <p><a class="btn btn-primary w-100 py-1" href="https://github.com/lil2kki/Open-Geode-Index#how-to-install" target="_blank">Download proxy mod for Geode Loader!</a></p>
            <h3>Submit a mod</h3>
            <hr class="my-1 mb-3">
            <?php if (!$user): ?>
                <div class="alert alert-warning">Please <a href="/login">sign in with GitHub</a> to submit mods.</div>
            <?php else: ?>
                <p class="text-muted">You can post anything you want but malware, pls provide us valid GitHub Repository cuz logo loading form it (user/repo/HEAD/logo.png)<br><br>You also can upload not your mods, but it would be sweet if you go to mod page and change developer displayname on real one instead you.<br><br>If you are developer and ownership of your repository was taken pls <a target="_blank" href="https://github.com/lil2kki/Open-Geode-Index/issues/new">send report here</a> so i give you access.</p>
                <form method="post" action="/v1/mods" class="h-100">
                    <input type="hidden" name="csrf" value="<?=htmlspecialchars(CSRF_TOKEN, ENT_QUOTES)?>">
                    <div class="form-group">
                        <label for="repo">Repository (user/repo)</label>
                        <input id="repo" name="repo" class="form-control" placeholder="lil2kki/mod" required>
                    </div>
                    <div class="form-group my-2">
                        <label for="download_link">Download link (.geode)</label>
                        <input id="download_link" name="download_link" class="form-control" placeholder="https://github.com/.../releases/download/vX.Y/file.geode" required>
                    </div>
                    <button class="w-100 btn btn-primary">Submit</button>
                </form>
                <?=asAPIReqForm()?>
            <?php endif; ?>
        </div>

        <div class="col-md-8 mt-1 pt-1">
            <div class="filter-section">
                <div class="row g-2">
                    <div class="col-lg-4 col-xxl-7">
                        <input type="text" id="mod-search" class="form-control form-control-sm" placeholder="Search..." autocomplete="off">
                    </div>
                    <div class="col-lg-4 col-xxl-3">
                        <select id="mod-sort" class="form-select form-select-sm">
                            <option value="downloads">Sort: Downloads</option>
                            <option value="recently_updated">Sort: Recently updated</option>
                            <option value="recently_published">Sort: Recently published</option>
                            <option value="name">Sort: IDs A-Z</option>
                            <option value="name_reverse">Sort: IDs Z-A</option>
                            <option value="oldest">Sort: Oldest</option>
                        </select>
                    </div>
                    <div class="col-lg-2 col-xxl-1">
                        <select id="mod-perpage" class="form-select form-select-sm">
                            <option value="8" selected>8</option>
                            <option value="12">12</option>
                            <option value="24">24</option>
                            <option value="48">48</option>
                            <option value="96">96</option>
                        </select>
                    </div>
                    <div class="col-lg-2 col-xxl-1">
                        <button id="mod-apply-filters" class="btn btn-primary btn-sm w-100">Apply</button>
                    </div>
                </div>
                <div class="row mt-2">
                    <div class="col-12">
                        <div class="d-flex flex-wrap align-items-center gap-2">
                            <div id="mod-tags-filter" class="d-flex flex-wrap gap-1" style="justify-content: center;">
                                <span class="text-secondary small">Loading tags...</span>
                            </div>
                            <button id="mod-clear-tags" class="d-none">Clear.</button>
                        </div>
                    </div>
                </div>
            </div>

            <div id="mods-container">
                <div class="row p-2" style="justify-content:space-around;align-items:stretch;display:flex;" id="mods-grid">
                    <?php for ($i = 0; $i < 8; $i++): ?>
                        <div class="skeleton-card" style="width:100%;margin:4px;"></div>
                    <?php endfor; ?>
                </div>
                <div class="pagination-bar">
                    <span class="page-info text-secondary" id="mod-page-info">Loading...</span>
                    <div>
                        <button id="mod-prev-page" class="btn btn-sm btn-outline-secondary" disabled>< Prev</button>
                        <button id="mod-next-page" class="btn btn-sm btn-outline-secondary" disabled>Next ></button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
    (function() {
        const state = { query: '', tags: [], sort: 'downloads', perPage: 8, page: 1, total: 0, data: [], loading: false, availableTags: [] };
        const grid = document.getElementById('mods-grid');
        const searchInput = document.getElementById('mod-search');
        const sortSelect = document.getElementById('mod-sort');
        const perPageSelect = document.getElementById('mod-perpage');
        const applyBtn = document.getElementById('mod-apply-filters');
        const prevBtn = document.getElementById('mod-prev-page');
        const nextBtn = document.getElementById('mod-next-page');
        const pageInfo = document.getElementById('mod-page-info');
        const tagsContainer = document.getElementById('mod-tags-filter');
        const clearTagsBtn = document.getElementById('mod-clear-tags');
        const statTotal = document.getElementById('stat-total-mods');

        function esc(str) { if (!str) return ''; const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }
        function strip(html) { if (!html) return ''; const d = document.createElement('div'); d.innerHTML = html; return d.textContent || ''; }

        function buildUrl() {
            const p = new URLSearchParams();
            if (state.query) p.set('query', state.query);
            if (state.tags.length) p.set('tags', state.tags.join(','));
            if (state.sort) p.set('sort', state.sort);
            p.set('per_page', state.perPage);
            p.set('page', state.page);
            return '/v1/mods?' + p.toString();
        }

        function renderSkeletons() { grid.innerHTML = Array.from({length:8}, () => `<div class="skeleton-card" style="width:100%;margin:4px;"></div>`).join(''); }

        function renderMods(mods) {
            if (!mods || mods.length === 0) { grid.innerHTML = `<div class="col-12 empty-state"><p>No mods found.</p></div>`; return; }
            let html = '';
            for (const m of mods) {
                const name = m.versions?.[0]?.name || m.id || 'Unnamed';
                const desc = m.versions?.[0]?.description || m.about || '';
                const logo = m.logo_url || '';
                const downloads = m.download_count ?? 0;
                const tags = (m.tags || []).slice(0, 5);
                const modId = m.id || '';
                html += `<a class="btn btn-outline-secondary card h-100 p-2 mt-2 mod-card" href="/ui/mod/${encodeURIComponent(modId)}" style="display:flex;text-align:start;text-decoration:none;width:100%;position:relative;">
                    <div style="display:flex;text-align:start;width:100%;">
                        <div style="width:72px;display:flex;justify-content:center;"><img src="${esc(logo)}" alt="" style="max-height:72px;min-width: 72px;" onerror="this.style.opacity='0.5';this.style.backdropFilter='brightness(0.5)';this.style.borderStyle='outset';this.style.borderWidth='3px 3px';"></div>
                        <div class="ms-2" style="display:flex;flex-direction:column;justify-content:space-between;flex:1;min-width:0;">
                            <div class="mod-title-row"><h3 class="m-0 p-0" style="font-size:1.5rem;">${esc(name)}</h3><div class="tags-row">${tags.map(t=>`<span class="tag-badge">${esc(t)}</span>`).join('')}</div></div>
                            <p class="m-0 p-0 text-body-tertiary" style="max-height:22px;font-size:0.8rem;">${esc(modId)}</p>
                            <p class="m-0 pb-1 text-muted" style="font-size:0.85rem;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;">${desc ? esc(strip(desc)) : ''}</p>
                        </div>
                    </div>
                    <span class="downloads-badge"><i class="bi bi-download"></i> ${downloads}</span>
                </a>`;
            }
            grid.innerHTML = html;
        }

        function updatePagination() {
            const totalPages = Math.ceil(state.total / state.perPage) || 1;
            pageInfo.textContent = `Showing ${state.data.length} of ${state.total} mods · Page ${state.page} of ${totalPages}`;
            prevBtn.disabled = state.page <= 1 || state.total === 0;
            nextBtn.disabled = state.page >= totalPages || state.total === 0;
            if (statTotal) statTotal.textContent = state.total;
        }

        async function fetchAvailableTags() {
            try {
                const r = await fetch('/v1/detailed-tags');
                if (!r.ok) return;
                const d = await r.json();
                if (d.error) return;
                state.availableTags = d.payload || [];
                renderTagButtons();
            } catch (e) { tagsContainer.innerHTML = '<span class="alert alert-danger text-center">Tags unavailable</span>'; }
        }

        function renderTagButtons() {
            if (!state.availableTags.length) { tagsContainer.innerHTML = '<span class="alert alert-danger text-center">No tags</span>'; return; }
            let html = '';
            for (const t of state.availableTags) {
                const name = typeof t === 'string' ? t : (t.name || t.display_name || '');
                if (!name) continue;
                const active = state.tags.includes(name) ? 'active' : '';
                html += `<button class="tag-btn ${active}" data-tag="${esc(name)}">${esc(name)}</button>`;
            }
            tagsContainer.innerHTML = html;
            clearTagsBtn.style.display = state.tags.length ? 'inline-block' : 'none';
            tagsContainer.querySelectorAll('.tag-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const tag = this.dataset.tag;
                    const idx = state.tags.indexOf(tag);
                    if (idx >= 0) state.tags.splice(idx, 1); else state.tags.push(tag);
                    state.page = 1; updateUrl(); fetchMods();
                });
            });
        }

        async function fetchMods() {
            if (state.loading) return;
            state.loading = true;
            renderSkeletons();
            try {
                const resp = await fetch(buildUrl());
                if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                const data = await resp.json();
                if (data.error) throw new Error(data.error);
                state.total = data.payload?.count ?? 0;
                state.data = data.payload?.data || [];
                renderMods(state.data);
                updatePagination();
                renderTagButtons();
            } catch (err) {
                grid.innerHTML = `<div class="alert alert-danger text-center">Failed to load mods</div>`;
                pageInfo.textContent = 'Error loading mods';
            } finally { state.loading = false; }
        }

        function updateUrl() {
            const p = new URLSearchParams();
            if (state.query) p.set('query', state.query);
            if (state.tags.length) p.set('tags', state.tags.join(','));
            if (state.sort && state.sort !== 'downloads') p.set('sort', state.sort);
            if (state.perPage && state.perPage !== 24) p.set('per_page', state.perPage);
            if (state.page > 1) p.set('page', state.page);
            window.history.replaceState({}, '', window.location.pathname + (p.toString() ? '?' + p.toString() : ''));
        }

        function loadFromUrl() {
            const p = new URLSearchParams(window.location.search);
            if (p.get('query')) { state.query = p.get('query'); searchInput.value = state.query; }
            if (p.get('tags')) state.tags = p.get('tags').split(',').filter(Boolean);
            if (p.get('sort') && ['downloads','recently_updated','recently_published','name','name_reverse','oldest'].includes(p.get('sort'))) { state.sort = p.get('sort'); sortSelect.value = state.sort; }
            if ([12,24,48,96].includes(parseInt(p.get('per_page'), 10))) { state.perPage = parseInt(p.get('per_page'), 10); perPageSelect.value = state.perPage; }
            if (parseInt(p.get('page'), 10) > 0) state.page = parseInt(p.get('page'), 10);
        }

        function applyFilters() {
            state.query = searchInput.value.trim();
            state.sort = sortSelect.value;
            state.perPage = parseInt(perPageSelect.value, 10) || 24;
            state.page = 1; updateUrl(); fetchMods();
        }

        async function init() {
            loadFromUrl();
            await fetchAvailableTags();
            await fetchMods();
            searchInput.addEventListener('keydown', e => { if (e.key === 'Enter') applyFilters(); });
            applyBtn.addEventListener('click', applyFilters);
            sortSelect.addEventListener('change', function() { state.sort = this.value; state.page = 1; updateUrl(); fetchMods(); });
            perPageSelect.addEventListener('change', function() { state.perPage = parseInt(this.value, 10) || 24; state.page = 1; updateUrl(); fetchMods(); });
            prevBtn.addEventListener('click', function() { if (state.page > 1) { state.page--; updateUrl(); fetchMods(); } });
            nextBtn.addEventListener('click', function() { const t = Math.ceil(state.total / state.perPage) || 1; if (state.page < t) { state.page++; updateUrl(); fetchMods(); } });
            clearTagsBtn.addEventListener('click', function() { state.tags = []; state.page = 1; updateUrl(); fetchMods(); });
        }
        init();
    })();
    </script>
    <?php
    ui_footer();
}

function render_mod_page($id) {
    $mods = db_read('mods.json') ?: [];
    $mod = null;
    foreach ($mods as $m) if ($m['id'] === $id) { $mod = $m; break; }
    $user = current_user();
    $is_admin = is_admin();

    if (!$mod) {
        http_response_code(404);
        echo "<script>window.location.replace('https://geode-sdk.org/mods/" . htmlspecialchars($id, ENT_QUOTES) . "');</script>";
        exit;
    }

    ui_header(
        htmlspecialchars($mod['versions'][0]['name'] ?? $mod['id']) . ' on Open Geode Index',
        $mod['versions'][0]['description'] ?? '',
        htmlspecialchars($mod['logo_url'] ?? '')
    );

    if ((empty($mod['about']) || !empty($mod['prefer_github_info'])) && !empty($mod['repo'])) {
        $text = fetch_github_raw_text($mod['repo'], 'README.md');
        if ($text === null) $text = fetch_github_raw_text($mod['repo'], 'about.md');
        if ($text !== null) $mod['about'] = $text;
    }

    $owner_allowed = is_admin();
    if (!$owner_allowed && $user) {
        foreach ($mod['developers'] as $dev) if (!empty($dev['username']) && $dev['username'] === $user && !empty($dev['is_owner'])) { $owner_allowed = true; break; }
    }

    $owner_display = '';
    foreach ($mod['developers'] as $d) if (!empty($d['is_owner'])) { $owner_display = $d['display_name'] ?? ($d['username'] ?? ''); break; }
    ?>
<style>
    .dev-card { border: 1px solid var(--bs-border-color); transition: all 0.2s; }
    .dev-card.bg-gradient { background: linear-gradient(135deg, var(--bs-primary-bg-subtle), var(--bs-secondary-bg)); }
    .dev-card .dev-avatar { height: 64px; width: 64px; object-fit: cover; border-radius: 4px 0 0 4px; }
</style>

<script>window.__CSRF__ = <?=json_encode(CSRF_TOKEN)?>;</script>

<div class="row">
  <div class="col-md-8">
    <div style="display: flex;gap: 12px;align-items: flex-start;">
        <div style="max-width: 112px; text-align: center;">
            <?php if (!empty($mod['logo_url'])): ?>
                <img src="<?=htmlspecialchars($mod['logo_url'])?>" alt="Mod logo..." style="max-height:95px; width:auto;" onerror="this.style.opacity='0.5'; this.style.backdropFilter='brightness(0.5)'; this.style.borderStyle='outset'; this.style.borderWidth='3px 3px';">
            <?php endif; ?>
            <span style="width: 100%; display: block; margin-top: 4px;" class="likebtn-wrapper" data-theme="black" data-ef_voting="push" data-show_like_label="false" data-popup_style="dark" data-share_size="small" data-loader_show="true" data-identifier="<?=htmlspecialchars($mod['id'])?>"></span>
            <script>(function(d,e,s){if(d.getElementById("likebtn_wjs"))return;a=d.createElement(e);m=d.getElementsByTagName(e)[0];a.async=1;a.id="likebtn_wjs";a.src=s;m.parentNode.insertBefore(a, m)})(document,"script","//w.likebtn.com/js/w/widget.js");</script>
        </div>
        <div style="flex:1; min-width:0;">
            <h2 class="m-0"><?=htmlspecialchars($mod['versions'][0]['name'] ?? $mod['id'])?></h2>
            <h5 class="m-0 mb-1 text-body-tertiary" style="font-size:0.9rem;"><?=htmlspecialchars($mod['id'])?></h5>
            <?php if (!empty($mod['versions'][0]['description'])): ?>
                <span class="text-muted"><?=htmlspecialchars($mod['versions'][0]['description'])?></span>
            <?php endif; ?>
        </div>
    </div>

    <ul class="nav nav-underline mx-1 mt-2" style="justify-content: center;">
        <li class="nav-item"><a class="nav-link active" data-toggle="tab" href="#about">About</a></li>
        <li class="nav-item"><a class="nav-link <?php if (empty($mod['changelog'])): ?>disabled<?php endif; ?>" data-toggle="tab" href="#changelog">Changelog</a></li>
    </ul>

    <div class="tab-content mt-1">
        <div class="tab-pane active" id="about"><p class="mb-0"><?=md(strip_tags($mod['about'] ?? ''))?></p></div>
        <?php if (!empty($mod['changelog'])): ?>
            <div class="tab-pane" id="changelog"><p class="mb-0"><?=md(strip_tags($mod['changelog']))?></p></div>
        <?php endif; ?>
    </div>
  </div>

  <div class="col-md-4">
    <hr>
    <?php if (!empty($mod['tags']) && is_array($mod['tags'])): ?>
        <h4>Tags</h4>
        <?php foreach ($mod['tags'] as $tag): ?>
            <span style="font-size:0.7rem;padding:2px 10px;border-radius:12px;background:var(--bs-secondary-bg);color:var(--bs-secondary-color);text-transform:capitalize;"><?=htmlspecialchars($tag)?></span>
        <?php endforeach; ?>
    <?php endif; ?>

    <h4 class="mt-2">Versions</h4>
    <ul class="list-group mb-2" style="max-height: 220px; overflow-y: auto;">
      <?php foreach ($mod['versions'] as $v): ?>
        <li class="list-group-item d-flex justify-content-between align-items-center">
          <div><strong><?=htmlspecialchars($v['version'])?></strong></div>
          <div style="display: flex; align-items: center;">
              <div><i class="bi bi-download"></i> <?=htmlspecialchars($v['download_count'] ?? 0)?></div>
              <a class="ms-2 btn btn-sm btn-success" href="/v1/mods/<?=urlencode($mod['id'])?>/versions/<?=urlencode($v['version'])?>/download">Download</a>
          </div>
        </li>
      <?php endforeach; ?>
    </ul>

    <h5>Developers</h5>
    <div style="max-height: 220px; overflow-y: auto;">
      <?php foreach ($mod['developers'] as $d): ?>
        <div class="mb-2 card dev-card <?php if (($d['username'] ?? null) === $user): ?>bg-gradient<?php endif; ?>">
            <div style="display: flex;">
                <img id="ic-<?=htmlspecialchars($d['username'])?>" src="https://github.com/<?=htmlspecialchars($d['username'])?>.png" class="rounded-start dev-avatar" alt="<?=htmlspecialchars($d['username'])?>">
                <img id="ic-<?=htmlspecialchars($d['display_name'])?>" class="rounded-start dev-avatar" style="display: none;"
                    src="https://github.com/<?=htmlspecialchars($d['display_name'])?>.png"
                    alt="<?=htmlspecialchars($d['display_name'])?>"
                    onload="this.style.display='block';document.getElementById('ic-<?=htmlspecialchars($d['username'])?>').style.display='none';document.getElementById('a-<?=htmlspecialchars($d['display_name'])?>').href='https://github.com/<?=htmlspecialchars($d['display_name'])?>';">
                <div class="border-start border-2 flex-grow-1">
                    <div class="card-body p-1 px-2 pt-2 d-flex justify-content-between align-items-start">
                        <div>
                            <h5 class="card-title mb-1">
                                <a id="a-<?=htmlspecialchars($d['display_name'])?>" target="_blank" href="https://github.com/<?=htmlspecialchars($d['username'])?>" class="link-body-emphasis link-offset-2 link-underline-opacity-25 link-underline-opacity-75-hover">
                                    <?=htmlspecialchars($d['display_name'] ?? $d['username'])?>
                                </a>
                            </h5>
                            <p class="card-text text-body-secondary" style="font-size:0.8rem; margin:0;">
                                <?=htmlspecialchars($d['username'])?>
                                <?php $role = !empty($d['role']) ? $d['role'] : (!empty($d['is_owner']) ? 'Owner' : 'Developer'); ?>
                                <span class="badge <?=!empty($d['is_owner']) ? 'text-bg-info' : 'text-bg-secondary'?>"><?=htmlspecialchars($role)?></span>
                            </p>
                        </div>
                        <?php if ($owner_allowed): ?>
                        <form onsubmit="event.preventDefault();if(!confirm('Remove <?=htmlspecialchars(addslashes($d['username']))?> from this mod?')) return;fetch('/v1/mods/<?=urlencode($mod['id'])?>/developers/<?=urlencode($d['username'])?>', {method:'DELETE', headers:{'X-CSRF-Token': window.__CSRF__}}).then(r => { if (r.ok) location.reload(); else r.json().then(d => alert(d.error || 'Failed')).catch(() => alert('Failed')); });">
                            <button type="submit" class="btn btn-sm btn-outline-danger">✕</button>
                        </form>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
      <?php endforeach; ?>
    </div>

    <?php if ($owner_allowed): ?>
      <div class="card mb-2">
        <div class="card-body">
          <h6>Add / update developer</h6>
          <form onsubmit="event.preventDefault();fetch('/v1/mods/<?=urlencode($mod['id'])?>/developers', {method: 'POST', body: new FormData(this), headers:{'X-CSRF-Token': window.__CSRF__}}).then(async r => { if (r.ok) { location.reload(); return; } let d; try { d = await r.json(); } catch (e) {} alert((d && d.error) || 'Failed to add developer'); });">
            <input name="username" class="form-control form-control-sm mb-2" placeholder="GitHub username" required>
            <select name="role" class="form-select form-select-sm mb-2">
              <option value="Developer">Developer</option>
              <option value="Owner">Owner</option>
              <option value="Porter">Porter</option>
              <option value="Contributor">Contributor</option>
            </select>
            <button class="w-100 btn btn-sm btn-primary">Add / update developer</button>
          </form>
        </div>
      </div>
    <?php endif; ?>

    <hr>

    <?php if ($owner_allowed): ?>
        <div class="card mb-2">
            <div class="card-body">
            <form id="mod-update-form" method="post" action="/v1/mods/<?=urlencode($mod['id'])?>">
                <input type="hidden" name="csrf" value="<?=htmlspecialchars(CSRF_TOKEN, ENT_QUOTES)?>">
                <h6>Update mod</h6>
                <div class="form-group my-2"><label class="form-label small">Tags (comma separated)</label>
                    <input name="tags" class="form-control form-control-sm" value="<?=htmlspecialchars(implode(', ', $mod['tags'] ?? []))?>" placeholder="utility, library, fun">
                </div>
                <div class="form-group my-2"><label class="form-label small">Text source:</label>
                    <select name="prefer_github_info" class="form-select form-select-sm">
                        <option value="0" <?=empty($mod['prefer_github_info']) ? 'selected' : ''?>>From .geode file</option>
                        <option value="1" <?=!empty($mod['prefer_github_info']) ? 'selected' : ''?>>From GitHub Repository</option>
                    </select>
                </div>
                <div class="form-group my-2"><label class="form-label small">Owner display name</label>
                    <input name="owner_display_name" class="form-control form-control-sm" value="<?=htmlspecialchars($owner_display)?>">
                </div>
                <div class="form-group my-2"><label class="form-label small">About / page text</label>
                    <textarea name="about" class="form-control form-control-sm" rows="4"><?=htmlspecialchars($mod['about'] ?? '')?></textarea>
                </div>
                <div class="form-group my-2"><label class="form-label small">Logo URL</label>
                    <input name="logo_url" class="form-control form-control-sm" value="<?=htmlspecialchars($mod['logo_url'] ?? '')?>">
                </div>
                <div class="form-group my-2 form-check">
                    <input type="checkbox" id="refresh_metadata" name="refresh_metadata" value="1" class="form-check-input">
                    <label for="refresh_metadata" class="form-check-label small">Re-sync from .geode</label>
                </div>
                <div class="form-group my-2"><label class="form-label small">New version download link</label>
                    <input name="download_link" class="form-control form-control-sm" placeholder="https://...">
                </div>
                <button class="w-100 btn btn-primary btn-sm">Save changes</button>
            </form>
            <?=asAPIReqForm('#mod-update-form')?>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($owner_allowed): ?>
      <div class="mb-2 alert alert-danger">
        <div class="card-body">
          <form method="post" action="/v1/mods/<?=urlencode($mod['id'])?>"
      onsubmit="event.preventDefault();if(!confirm('Delete <?=htmlspecialchars($mod['id'])?>?\nAction can\'t be undone...')) return;fetch(this.action, {method:'POST', body:new FormData(this), headers:{'X-CSRF-Token': window.__CSRF__}}).then(() => {history.back(); setTimeout(()=>location.reload(), 200)});">
            <input type="hidden" name="_method" value="DELETE">
            <input type="hidden" name="csrf" value="<?=htmlspecialchars(CSRF_TOKEN, ENT_QUOTES)?>">
            <button type="submit" class="w-100 btn btn-sm btn-outline-danger">Delete mod</button>
          </form>
        </div>
      </div>
    <?php endif; ?>

    <?php if (is_admin()): ?>
      <div class="card">
        <div class="card-body">
          <form method="post" action="/ui/admin">
            <input type="hidden" name="csrf" value="<?=htmlspecialchars(CSRF_TOKEN, ENT_QUOTES)?>">
            <input type="hidden" name="action" value="toggle_featured">
            <input type="hidden" name="modid" value="<?=htmlspecialchars($mod['id'])?>">
            <select name="featured" class="form-select form-select-sm my-1">
                <option value="0" <?=empty($mod['featured']) ? 'selected' : ''?>>Featured: No</option>
                <option value="1" <?=!empty($mod['featured']) ? 'selected' : ''?>>Featured: Yes</option>
            </select>
            <button class="w-100 btn btn-sm btn-outline-danger">Apply</button>
          </form>
        </div>
      </div>
    <?php endif; ?>
  </div>

  <?php if (!empty($mod['repository'])): ?>
    <span class="w-100 text-center small">Repository: <a href="<?=htmlspecialchars($mod['repository'])?>" target="_blank"><?=htmlspecialchars($mod['repository'])?></a></span>
  <?php endif; ?>
</div>
<?php
    ui_footer();
}

function render_devs() {
    $developers = db_read('developers.json') ?: [];
    $user = current_user();
    ui_header('Users - Open Geode Index', "List of developers that logined once.");
    ?>
    <div class="row px-3" style="justify-content: space-around; align-items: center; align-items: stretch; display: flex;">
      <?php if (empty($developers)): ?>
        <div class="col-12"><div class="alert alert-danger">But nobody came.</div></div>
      <?php else: foreach ($developers as $dev): ?>
        <div style="text-align: center; <?php if (($dev['username'] ?? null) === $user): ?> order: -1; <?php endif; ?>" class="col-sm-4 col-lg-2 p-2">
          <div class="card h-100 pt-3 <?php if (($dev['username'] ?? null) === $user): ?> bg-gradient <?php endif; ?>">
            <img class="card-img-top" src="https://github.com/<?=htmlspecialchars($dev['username'])?>.png" alt="Avatar..." style="object-fit:scale-down;height:140px;" onerror="this.style.opacity='0.5'; this.style.backdropFilter='brightness(0.5)'; this.style.borderStyle='outset'; this.style.borderWidth='3px 3px';">
            <div class="card-body d-flex flex-column">
              <h5 class="card-title mb-1">
                <a target="_blank" href="https://github.com/<?=htmlspecialchars($dev['username'])?>" class="link-body-emphasis link-offset-2 link-underline-opacity-25 link-underline-opacity-75-hover"><?=htmlspecialchars($dev['display_name'])?></a>
              </h5>
              <p class="card-text text-muted"><?=htmlspecialchars($dev['username'])?></p>
            </div>
          </div>
        </div>
      <?php endforeach; endif; ?>
    </div>
<?php
    ui_footer();
}

function render_install() {
    $user = current_user();
    ui_header('Installing Open Geode Index...', "Info about installing our proxy mod for Geode Loader!");
    ?>
<div class="row">
    <div class="col-md-6 fs-5">
        <?=md('
<h3>How to install the mod:</h3>

- Download latest version of mod: <a class="btn btn-primary btn-sm" href="https://github.com/lil2kki/Open-Geode-Index/releases/latest/download/lil2kki.open-geode-index.geode">lil2kki.open-geode-index.geode</a>
- Open Geode Loader Settings
- Click the "Install From File" button
- Select downloaded file and confirm
        ')?>
    </div>
    <div class="col-md-6"><img style="max-width: 100%;" alt="image" src="https://github.com/user-attachments/assets/dc4987df-b2fa-430f-8610-66bf4ce64862"/></div>
</div>
<?php
    ui_footer();
}

function render_admin_page() {
    if (!is_admin()) { http_response_code(403); echo "<h1>Forbidden</h1><p>Admin only</p>"; exit; }

    $tab = $_GET['tab'] ?? 'mods';
    ui_header('Admin - Open Geode Index');
    $mods = db_read('mods.json') ?: [];
    $devs = db_read('developers.json') ?: [];
    $loader_versions = db_read('loader_versions.json') ?: [];
    $tags = db_read('tags.json') ?: [];
    $deprec = db_read('deprecations.json') ?: [];
    $stats = api_stats_payload();
    $csrf = htmlspecialchars(CSRF_TOKEN, ENT_QUOTES);
    ?>
<div class="row">
  <div class="col-12">
    <h2 class="h4">Admin panel</h2>
    <?php if (!empty($_SESSION['flash'])) { echo '<div class="alert alert-info">'.htmlspecialchars($_SESSION['flash']).'</div>'; unset($_SESSION['flash']); } ?>
    <ul class="nav nav-underline mb-3">
      <li class="nav-item"><a class="nav-link <?= $tab==='mods' ? 'active' : ''?>" href="/ui/admin?tab=mods">Mods</a></li>
      <li class="nav-item"><a class="nav-link <?= $tab==='loader' ? 'active' : ''?>" href="/ui/admin?tab=loader">Loader Versions</a></li>
      <li class="nav-item"><a class="nav-link <?= $tab==='developers' ? 'active' : ''?>" href="/ui/admin?tab=developers">Developers</a></li>
      <li class="nav-item"><a class="nav-link <?= $tab==='tags' ? 'active' : ''?>" href="/ui/admin?tab=tags">Tags</a></li>
      <li class="nav-item"><a class="nav-link <?= $tab==='deprecations' ? 'active' : ''?>" href="/ui/admin?tab=deprecations">Deprecations</a></li>
      <li class="nav-item"><a class="nav-link <?= $tab==='stats' ? 'active' : ''?>" href="/ui/admin?tab=stats">Stats</a></li>
      <li class="nav-item"><a class="nav-link <?= $tab==='tokens' ? 'active' : ''?>" href="/ui/admin?tab=tokens">Tokens</a></li>
    </ul>

    <?php if ($tab === 'mods'): ?>
      <h5>Mods</h5>
      <table class="table table-sm"><thead><tr><th>ID</th><th>Versions</th><th>Repo</th><th>Tags</th><th>Featured</th><th></th></tr></thead>
        <tbody>
        <?php foreach ($mods as $m): ?>
          <tr>
            <td><?=htmlspecialchars($m['id'])?></td>
            <td><?=count($m['versions'])?></td>
            <td><?=htmlspecialchars($m['repo'] ?? '')?></td>
            <td><?=htmlspecialchars(implode(', ', $m['tags'] ?? []))?></td>
            <td><?=!empty($m['featured']) ? 'yes' : 'no'?></td>
            <td><a class="btn btn-sm btn-outline-primary" href="/ui/mod/<?=urlencode($m['id'])?>">View</a></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>

    <?php elseif ($tab === 'loader'): ?>
      <h5>Create Loader Version</h5>
      <form method="post" action="/ui/admin">
        <input type="hidden" name="csrf" value="<?=$csrf?>">
        <input type="hidden" name="action" value="create_loader_version">
        <div class="form-row">
          <div class="form-group col-md-4"><label>Tag</label><input name="tag" class="form-control" required></div>
          <div class="form-group col-md-4"><label>Commit hash</label><input name="commit_hash" class="form-control" required></div>
          <div class="form-group col-md-4"><label>GD (json or k:v,comma)</label><input name="gd" class="form-control"></div>
        </div>
        <button class="btn btn-primary">Create version</button>
      </form>
      <h5 class="mt-4">Existing loader versions</h5>
      <table class="table table-sm"><thead><tr><th>Tag</th><th>GD</th><th>Commit</th><th>Created</th></tr></thead><tbody>
        <?php foreach ($loader_versions as $lv): ?>
          <tr><td><?=htmlspecialchars($lv['tag'])?></td><td><?=htmlspecialchars(json_encode($lv['gd']))?></td><td><?=htmlspecialchars($lv['commit_hash'] ?? '')?></td><td><?=htmlspecialchars($lv['created_at'] ?? '')?></td></tr>
        <?php endforeach; ?></tbody></table>

    <?php elseif ($tab === 'developers'): ?>
      <h5>Developers</h5>
      <table class="table table-sm"><thead><tr><th>ID</th><th>Username</th><th>Display</th><th>Verified</th><th>Admin</th><th>Actions</th></tr></thead><tbody>
        <?php foreach ($devs as $d): ?>
          <tr>
            <td><?=htmlspecialchars($d['id'])?></td>
            <td><a target="_blank" href="https://github.com/<?=htmlspecialchars($d['username'])?>"><?=htmlspecialchars($d['username'])?></a></td>
            <td><?=htmlspecialchars($d['display_name'])?></td>
            <td><?=!empty($d['verified']) ? 'yes' : 'no'?></td>
            <td><?=!empty($d['admin']) ? 'yes' : 'no'?></td>
            <td>
              <form method="post" action="/ui/admin" style="display:inline-block">
                <input type="hidden" name="csrf" value="<?=$csrf?>">
                <input type="hidden" name="action" value="update_developer">
                <input type="hidden" name="developer_id" value="<?=htmlspecialchars($d['id'])?>">
                <select name="admin" class="form-control form-control-sm d-inline-block" style="width:auto">
                  <option value="0" <?=empty($d['admin']) ? 'selected':''?>>No</option>
                  <option value="1" <?=!empty($d['admin']) ? 'selected':''?>>Yes</option>
                </select>
                <select name="verified" class="form-control form-control-sm d-inline-block" style="width:auto">
                  <option value="0" <?=empty($d['verified']) ? 'selected':''?>>No</option>
                  <option value="1" <?=!empty($d['verified']) ? 'selected':''?>>Yes</option>
                </select>
                <button class="btn btn-sm btn-outline-primary">Update</button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?></tbody></table>

    <?php elseif ($tab === 'tags'): ?>
      <h5>Tags</h5>
      <form method="post" action="/ui/admin" class="form-inline mb-3">
        <input type="hidden" name="csrf" value="<?=$csrf?>">
        <input type="hidden" name="action" value="create_tag">
        <input name="tag_name" class="form-control mr-2" placeholder="tag name">
        <button class="btn btn-primary">Add tag</button>
      </form>
      <ul><?php foreach ($tags as $t) echo '<li>'.htmlspecialchars(is_array($t)&&isset($t['name'])?$t['name']:(string)$t).'</li>'; ?></ul>

    <?php elseif ($tab === 'deprecations'): ?>
      <h5>Deprecations</h5>
      <form method="post" action="/ui/admin" class="mb-3">
        <input type="hidden" name="csrf" value="<?=$csrf?>">
        <input type="hidden" name="action" value="create_deprecation">
        <div class="form-row">
          <div class="form-group col-md-3"><label>Mod ID</label><input name="modid" class="form-control"></div>
          <div class="form-group col-md-4"><label>By (comma)</label><input name="by" class="form-control"></div>
          <div class="form-group col-md-5"><label>Reason</label><input name="reason" class="form-control"></div>
        </div>
        <button class="btn btn-primary">Create</button>
      </form>
      <table class="table table-sm"><thead><tr><th>Mod</th><th>By</th><th>Reason</th><th>Actions</th></tr></thead><tbody>
        <?php foreach ($deprec as $d): ?>
          <tr><td><?=htmlspecialchars($d['mod_id'])?></td><td><?=htmlspecialchars(implode(', ', (array)$d['by']))?></td><td><?=htmlspecialchars($d['reason'])?></td>
            <td><form method="post" action="/ui/admin"><input type="hidden" name="csrf" value="<?=$csrf?>"><input type="hidden" name="action" value="delete_deprecation"><input type="hidden" name="modid" value="<?=htmlspecialchars($d['mod_id'])?>"><input type="hidden" name="depid" value="<?=htmlspecialchars($d['id'])?>"><button class="btn btn-sm btn-danger">Delete</button></form></td></tr>
        <?php endforeach; ?></tbody></table>

    <?php elseif ($tab === 'stats'): ?>
      <h5>Stats</h5>
      <dl class="row">
        <dt class="col-sm-4">Total geode downloads</dt><dd class="col-sm-8"><?=htmlspecialchars($stats['total_geode_downloads'] ?? 0)?></dd>
        <dt class="col-sm-4">Total mod count</dt><dd class="col-sm-8"><?=htmlspecialchars($stats['total_mod_count'] ?? 0)?></dd>
        <dt class="col-sm-4">Total mod downloads</dt><dd class="col-sm-8"><?=htmlspecialchars($stats['total_mod_downloads'] ?? 0)?></dd>
        <dt class="col-sm-4">Total registered developers</dt><dd class="col-sm-8"><?=htmlspecialchars($stats['total_registered_developers'] ?? 0)?></dd>
      </dl>

    <?php elseif ($tab === 'tokens'): ?>
      <h5>Your tokens</h5>
      <?php $tokens = db_read('tokens.json') ?: []; $current = current_user(); ?>
      <table class="table table-sm"><thead><tr><th>Access token</th><th>Expires at</th><th>Refresh token</th><th>Refresh expires</th><th>Action</th></tr></thead><tbody>
        <?php foreach ($tokens as $k => $meta) {
          if (($meta['username'] ?? null) === $current) {
            echo '<tr><td>'.htmlspecialchars($k).'</td><td>'.htmlspecialchars($meta['expires_at'] ?? '').'</td><td>'.htmlspecialchars($meta['refresh_token'] ?? '').'</td><td>'.htmlspecialchars($meta['refresh_expires_at'] ?? '').'</td><td><form method="post" action="/ui/admin"><input type="hidden" name="csrf" value="'.$csrf.'"><input type="hidden" name="action" value="revoke_token"><input type="hidden" name="token" value="'.htmlspecialchars($k).'"><button class="btn btn-sm btn-danger">Revoke</button></form></td></tr>';
          }
        } ?>
      </tbody></table>
    <?php endif; ?>
  </div>
</div>
<?php
    ui_footer();
}

function api_stats_payload() {
    $mods = db_read('mods.json') ?: [];
    $devs = db_read('developers.json') ?: [];
    $total_mod_downloads = 0;
    foreach ($mods as $m) $total_mod_downloads += ($m['download_count'] ?? 0);
    return [
        'total_geode_downloads'       => 0,
        'total_mod_count'             => count($mods),
        'total_mod_downloads'         => $total_mod_downloads,
        'total_registered_developers' => count($devs),
    ];
}

/* ======================= Admin UI form handler ======================= */

function handle_admin_form() {
    if (!is_admin()) { http_response_code(403); echo "<h1>Forbidden</h1><p>Admin only</p>"; exit; }

    // [PATCH] CSRF для admin-форм
    if (!hash_equals(CSRF_TOKEN, (string)($_POST['csrf'] ?? ''))) {
        http_response_code(403);
        echo "<h1>403 CSRF</h1>";
        exit;
    }

    $action = $_POST['action'] ?? '';

    if ($action === 'toggle_featured') {
        $modid = $_POST['modid'] ?? null;
        $featured = !empty($_POST['featured']);
        $mods = db_read('mods.json') ?: [];
        foreach ($mods as $i => $m) {
            if ($m['id'] === $modid) {
                $mods[$i]['featured'] = $featured;
                $mods[$i]['updated_at'] = iso8601_utc();
                db_write('mods.json', $mods);
                $_SESSION['flash'] = 'Mod updated';
                header('Location: /ui/admin?tab=mods');
                exit;
            }
        }
        $_SESSION['flash'] = 'Mod not found';
        header('Location: /ui/admin?tab=mods');
        exit;
    }

    if ($action === 'create_loader_version') {
        $tag = $_POST['tag'] ?? null;
        $commit_hash = $_POST['commit_hash'] ?? null;
        $gd = $_POST['gd'] ?? null;
        if (!$tag || !$commit_hash || !$gd) {
            $_SESSION['flash'] = 'Missing fields';
            header('Location:/ui/admin?tab=loader');
            exit;
        }
        $gd_parsed = json_decode($gd, true);
        if ($gd_parsed === null) {
            $parts = array_map('trim', explode(',', $gd));
            $gd_parsed = [];
            foreach ($parts as $p) if (strpos($p, ':') !== false) { list($k, $v) = array_map('trim', explode(':', $p, 2)); if ($k && $v) $gd_parsed[$k] = $v; }
        }
        $_POST = ['tag' => $tag, 'commit_hash' => $commit_hash, 'gd' => $gd_parsed];
        return api_loader_versions_create();
    }

    if ($action === 'update_developer') {
        $id = intval($_POST['developer_id'] ?? 0);
        $body = [];
        if (isset($_POST['admin']))    $body['admin'] = (bool)$_POST['admin'];
        if (isset($_POST['verified'])) $body['verified'] = (bool)$_POST['verified'];
        $_POST = $body;
        return api_developers_update($id);
    }

    if ($action === 'create_tag') {
        $name = trim($_POST['tag_name'] ?? '');
        if ($name === '') { $_SESSION['flash'] = 'Tag name required'; header('Location:/ui/admin?tab=tags'); exit; }
        $tags = db_read('tags.json') ?: [];
        $tags[] = ['id' => time(), 'name' => $name, 'display_name' => $name, 'is_readonly' => false];
        db_write('tags.json', $tags);
        $_SESSION['flash'] = 'Tag created';
        header('Location:/ui/admin?tab=tags');
        exit;
    }

    if ($action === 'create_deprecation') {
        $modid = $_POST['modid'] ?? '';
        $by = isset($_POST['by']) ? array_map('trim', explode(',', $_POST['by'])) : [];
        $reason = $_POST['reason'] ?? '';
        $_POST = ['by' => $by, 'reason' => $reason];
        return api_deprecations_create($modid);
    }

    if ($action === 'delete_deprecation') {
        $modid = $_POST['modid'] ?? '';
        $depid = intval($_POST['depid'] ?? 0);
        return api_deprecations_delete($modid, $depid);
    }

    if ($action === 'revoke_token') {
        $token = $_POST['token'] ?? '';
        $tokens = db_read('tokens.json') ?: [];
        if (isset($tokens[$token])) { unset($tokens[$token]); db_write('tokens.json', $tokens); $_SESSION['flash'] = 'Token revoked'; }
        else $_SESSION['flash'] = 'Token not found';
        header('Location: /ui/admin?tab=tokens');
        exit;
    }

    $_SESSION['flash'] = 'Unknown admin action';
    header('Location: /ui/admin');
    exit;
}

/* ======================= WEB auth handlers ======================= */

function handle_login() {
    if (!defined('CLIENT_ID') || CLIENT_ID === '') {
        echo "<h1>GitHub OAuth not configured</h1><p>Please set CLIENT_ID and CLIENT_SECRET in _config.php</p>";
        exit;
    }
    $state = bin2hex(random_bytes(12));
    $_SESSION['oauth_state'] = $state;
    $params = http_build_query([
        'client_id'    => CLIENT_ID,
        'redirect_uri' => CALLBACK_URL ?: current_url_base() . '/callback',
        'scope'        => 'read:user',
        'state'        => $state,
    ]);
    header("Location: https://github.com/login/oauth/authorize?$params");
    exit;
}

function handle_callback() {
    if (isset($_GET['logout'])) {
        session_destroy();
        setcookie(SESSION_COOKIE, '', time() - 3600, '/');
        header('Location: /ui');
        exit;
    }
    if (!isset($_GET['code']) || !isset($_GET['state'])) { echo "Missing code or state"; exit; }
    if (!isset($_SESSION['oauth_state']) || $_SESSION['oauth_state'] !== $_GET['state']) { echo "Invalid state"; exit; }

    $token = github_exchange_code($_GET['code']);
    if (!$token) { echo "Failed to obtain access token"; exit; }

    $user = github_get_user($token);
    if (!$user || !isset($user['login'])) { echo "Failed to fetch GitHub user"; exit; }

    $_SESSION['github_user'] = $user['login'];
    $_SESSION['github_token'] = $token;
    ensure_developer_record($user['login'], $user['name'] ?? $user['login']);
    header('Location: /ui');
    exit;
}

function handle_logout() {
    session_destroy();
    setcookie(SESSION_COOKIE, '', time() - 3600, '/');
    header('Location: /ui');
    exit;
}

/* ======================= END OF FILE ======================= */
