<?php
include '_config.php';

define('DATA_DIR', __DIR__ . '/data');
define('SESSION_COOKIE', 'ogi_session');
define('ACCESS_TOKEN_TTL', 60 * 60 * 24 * 7);    // 7 days
define('REFRESH_TOKEN_TTL', 60 * 60 * 24 * 30);  // 30 days

@ini_set('display_errors', '0');
@ini_set('display_startup_errors', '0');
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);

ob_start();

// ensure data dir
if (!file_exists(DATA_DIR)) @mkdir(DATA_DIR, 0755, true);

/* ======================= BOOT ======================= */
session_start();
$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($uri !== '/' && substr($uri, -1) === '/') $uri = rtrim($uri, '/');
route($method, $uri);

/* ======================= ROUTER ======================= */
function route($method, $uri) {
    // UI routes
    if ($uri === '/' && $method === 'GET') return handle_home();
    if ($uri === '/ui' && $method === 'GET') return render_ui();
    if ($uri === '/developers' && $method === 'GET') return render_devs();
    if ($uri === '/login' && $method === 'GET') return handle_login();
    if ($uri === '/callback' && $method === 'GET') return handle_callback();
    if ($uri === '/logout' && $method === 'GET') return handle_logout();
    if (preg_match('#^/ui/mod/([^/]+)$#', $uri, $m) && $method === 'GET') return render_mod_page($m[1]);
    if ($uri === '/ui/admin' && $method === 'GET') return render_admin_page();
    if ($uri === '/ui/admin' && $method === 'POST') return handle_admin_form();

    // API endpoints (full /v1 surface)
    if ($uri === '/health' && $method === 'GET') { header('Content-Type: text/plain'); echo 'ok'; exit; }

    // tags
    if ($uri === '/v1/tags' && $method === 'GET') return api_tags_index();
    if ($uri === '/v1/detailed-tags' && $method === 'GET') return api_tags_detailed();

    // developers
    if ($uri === '/v1/developers' && $method === 'GET') return api_developers_index();
    if (preg_match('#^/v1/developers/(\d+)$#', $uri, $m)) {
        if ($method === 'GET') return api_developers_get(intval($m[1]));
        if ($method === 'PUT') return api_developers_update(intval($m[1]));
    }

    // auth
    if ($uri === '/v1/login/github' && $method === 'POST') return api_login_github();
    if ($uri === '/v1/login/github/callback' && $method === 'POST') return api_login_callback(); // supports POST as spec
    if ($uri === '/v1/login/github/poll' && $method === 'POST') return api_login_github_poll();
    if ($uri === '/v1/login/github/token' && $method === 'POST') return api_login_github_token();
    if ($uri === '/v1/login/github/web' && $method === 'POST') return api_login_github_web();
    if ($uri === '/v1/login/refresh' && $method === 'POST') return api_refresh_token();

    // me
    if ($uri === '/v1/me' && $method === 'GET') return api_get_me();
    if ($uri === '/v1/me' && $method === 'PUT') return api_put_me();
    if ($uri === '/v1/me/mods' && $method === 'GET') return api_get_own_mods();
    if ($uri === '/v1/me/token' && $method === 'DELETE') return api_delete_token();
    if ($uri === '/v1/me/tokens' && $method === 'DELETE') return api_delete_tokens();

    // loader versions
    if ($uri === '/v1/loader/versions' && $method === 'GET') return api_loader_versions_index();
    if ($uri === '/v1/loader/versions' && $method === 'POST') return api_loader_versions_create();
    if (preg_match('#^/v1/loader/versions/([^/]+)$#', $uri, $m) && $method === 'GET') return api_loader_versions_get($m[1]);

    // mods root
    if ($uri === '/v1/mods' && $method === 'GET') return api_mods_index();
    if ($uri === '/v1/mods' && $method === 'POST') return api_mods_create();

    // mods updates endpoint
    if ($uri === '/v1/mods/updates' && $method === 'GET') return api_mods_updates();

    // mod-specific endpoints
    if (preg_match('#^/v1/mods/([^/]+)$#', $uri, $m)) {
        if ($method === 'GET') return api_mods_get($m[1]);
        if ($method === 'PUT') return api_mods_update_admin($m[1]); // admin-only in spec
        if ($method === 'POST') {
            // HTML forms may simulate DELETE via _method=DELETE
            if (!empty($_POST['_method']) && strtoupper($_POST['_method']) === 'DELETE') {
                return api_mods_delete($m[1]);
            }
            return api_mods_update_owner($m[1]); // owner POST
        }
        if ($method === 'DELETE') return api_mods_delete($m[1]);
    }

    // deprecations
    if (preg_match('#^/v1/mods/([^/]+)/deprecations$#', $uri, $m)) {
        if ($method === 'GET') return api_deprecations_index($m[1]);
        if ($method === 'POST') return api_deprecations_create($m[1]);
        if ($method === 'DELETE') return api_deprecations_clear_all($m[1]);
    }
    if (preg_match('#^/v1/mods/([^/]+)/deprecations/(\d+)$#', $uri, $m)) {
        if ($method === 'PUT') return api_deprecations_update($m[1], intval($m[2]));
        if ($method === 'DELETE') return api_deprecations_delete($m[1], intval($m[2]));
    }

    // mod developers
    if (preg_match('#^/v1/mods/([^/]+)/developers$#', $uri, $m) && $method === 'POST') return api_mod_add_developer($m[1]);
    if (preg_match('#^/v1/mods/([^/]+)/developers/([^/]+)$#', $uri, $m) && $method === 'DELETE') return api_mod_remove_developer($m[1], $m[2]);

    // logo
    if (preg_match('#^/v1/mods/([^/]+)/logo$#', $uri, $m) && $method === 'GET') return api_mod_logo($m[1]);

    // versions
    if (preg_match('#^/v1/mods/([^/]+)/versions$#', $uri, $m)) {
        if ($method === 'GET') return api_mod_versions_index($m[1]);
        if ($method === 'POST') return api_mod_versions_create($m[1]);
    }
    if (preg_match('#^/v1/mods/([^/]+)/versions/([^/]+)$#', $uri, $m)) {
        if ($method === 'GET') return api_mod_versions_get($m[1], $m[2]);
        if ($method === 'PUT') return api_mod_versions_update($m[1], $m[2]);
    }
    if (preg_match('#^/v1/mods/([^/]+)/versions/([^/]+)/download$#', $uri, $m) && $method === 'GET') return api_mod_versions_download($m[1], $m[2]);

    // stats
    if ($uri === '/v1/stats' && $method === 'GET') return api_stats();

    // fallback
    if (strpos($uri, '/v1') === 0) {
        json_response(['error' => 'not found', 'payload' => null], 404);
    } else {
        http_response_code(404);
        echo "<h1>404 Not Found</h1><p>$uri</p>";
    }
    exit;
}

/* ======================= UTILITIES ======================= */

function md($a = 'a', $line = false) {
    include 'Parsedown.php';
    return $line ? preg_replace('/^#+\s*/m', '', Parsedown::instance()->line($a)) : Parsedown::instance()->text($a);
}

function compute_remote_sha256($url, $max_bytes = 120 * 1024 * 1024, $timeout = 60, $max_redirects = 8) {
    if (empty($url) || stripos($url, 'http') !== 0) {
        error_log("[OGI] compute_remote_sha256 invalid url: $url");
        return null;
    }

    $tmp = fetch_remote_file_to_temp($url, $max_bytes, $timeout, $max_redirects);
    if ($tmp === null) {
        error_log("[OGI] compute_remote_sha256 fetch failed for $url");
        return null;
    }

    $hash = @hash_file('sha256', $tmp);
    @unlink($tmp);
    if ($hash === false) {
        error_log("[OGI] compute_remote_sha256 hash_file failed for $url");
        return null;
    }
    return $hash;
}

function fetch_remote_file_to_temp($url, $max_bytes = 120 * 1024 * 1024, $timeout = 35, $max_redirects = 8) {
    if (empty($url) || stripos($url, 'http') !== 0) {
        error_log("[OGI] fetch_remote_file_to_temp invalid url: $url");
        return null;
    }
    $opts = [
        'http' => [
            'method'        => 'GET',
            'header'        => "User-Agent: Open-Geode-Index-PHP\r\nAccept: application/octet-stream\r\n",
            'timeout'       => $timeout,
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer'=>true,'verify_peer_name'=>true],
    ];
    $ctx = stream_context_create($opts);
    $current = $url;
    $redirects = 0;

    while ($redirects <= $max_redirects) {
        $headers = @get_headers($current, 1, $ctx);
        if ($headers === false) {
            error_log("[OGI] fetch_remote_file_to_temp get_headers failed for $current");
            return null;
        }
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
            $current = $loc;
            $redirects++;
            continue;
        }

        if ($code === null || $code < 200 || $code >= 300) {
            error_log("[OGI] fetch_remote_file_to_temp HTTP status $code for $current");
            return null;
        }
        break;
    }

    if ($redirects > $max_redirects) {
        error_log("[OGI] fetch_remote_file_to_temp too many redirects for $url");
        return null;
    }

    $ctx2 = stream_context_create($opts);
    $fp = @fopen($current, 'rb', false, $ctx2);
    if ($fp === false) {
        error_log("[OGI] fetch_remote_file_to_temp fopen failed for $current");
        return null;
    }

    $tmp = tempnam(sys_get_temp_dir(), 'ogi_');
    $out = @fopen($tmp, 'wb');
    if ($out === false) { fclose($fp); @unlink($tmp); return null; }

    $read = 0; $chunk = 8192;
    while (!feof($fp) && $read < $max_bytes) {
        $data = @fread($fp, $chunk);
        if ($data === false) break;
        $len = strlen($data);
        if ($len === 0) break;
        $read += $len;
        fwrite($out, $data);
    }
    fclose($fp); fclose($out);

    if ($read >= $max_bytes) { error_log("[OGI] fetch_remote_file_to_temp reached max_bytes for $current"); @unlink($tmp); return null; }
    return $tmp;
}

//['modjson'=>array|null,'about'=>string|null,'changelog'=>string|null]
function extract_metadata_from_geode($download_url) {
    if (empty($download_url)) return null;
    $tmp = fetch_remote_file_to_temp($download_url);
    if ($tmp === null) return null;

    if (!class_exists('ZipArchive')) {
        error_log("[OGI] extract_metadata_from_geode ZipArchive not available");
        @unlink($tmp);
        return null;
    }

    $zip = new ZipArchive();
    if ($zip->open($tmp) !== true) { error_log("[OGI] extract_metadata_from_geode zip open failed for $tmp"); @unlink($tmp); return null; }

    $result = ['modjson'=>null, 'about'=>null, 'changelog'=>null];
    $nameCount = $zip->numFiles;
    $found = ['mod.json'=>null, 'about'=>null, 'readme'=>null, 'changelog'=>null];

    for ($i = 0; $i < $nameCount; $i++) {
        $name = $zip->getNameIndex($i);
        $base = strtolower(basename($name));
        if ($base === 'mod.json' && $found['mod.json'] === null) $found['mod.json'] = $i;
        elseif (in_array($base, ['about.md','about','about.txt']) && $found['about'] === null) $found['about'] = $i;
        elseif (in_array($base, ['readme.md','readme','readme.txt']) && $found['readme'] === null) $found['readme'] = $i;
        elseif (in_array($base, ['changelog.md','changelog','change.log','changes.md','changelog']) && $found['changelog'] === null) $found['changelog'] = $i;
    }

    if ($found['mod.json'] !== null) {
        $raw = $zip->getFromIndex($found['mod.json']);
        if ($raw !== false) {
            $j = json_decode($raw, true);
            if ($j !== null) $result['modjson'] = $j;
        }
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
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
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
    file_put_contents($tmp, $s);
    @rename($tmp, $path);
    return true;
}

function json_input() {
    $raw = file_get_contents('php://input');
    if (!empty($raw)) {
        $j = json_decode($raw, true);
        if ($j !== null) return $j;
        if (strpos($raw, '=') !== false) {
            parse_str($raw, $p);
            return $p;
        }
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

// normalization helpers
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

function map_modjson_developers($devs, $submitter = null) {
    $out = [];
    if (empty($devs)) {
        if ($submitter) $out[] = ['id' => null, 'username' => $submitter, 'display_name' => $submitter, 'is_owner' => true];
        return $out;
    }
    foreach ($devs as $d) {
        if (is_string($d)) {
            $out[] = ['id' => null, 'username' => $d, 'display_name' => $d, 'is_owner' => false];
        } elseif (is_array($d)) {
            $username = isset($d['username']) ? $d['username'] : (isset($d['name']) ? $d['name'] : null);
            $display = isset($d['display_name']) ? $d['display_name'] : ($username ?: '');
            $is_owner = !empty($d['is_owner']);
            $out[] = ['id' => isset($d['id']) ? $d['id'] : null, 'username' => $username, 'display_name' => $display, 'is_owner' => $is_owner];
        }
    }
    if ($submitter) {
        $found = false;
        foreach ($out as &$o) {
            if ($o['username'] === $submitter) { $o['is_owner'] = true; $found = true; break; }
        }
        if (!$found) $out[] = ['id' => null, 'username' => $submitter, 'display_name' => $submitter, 'is_owner' => true];
    }
    return $out;
}

/* ======================= GITHUB helpers & token issuance ======================= */
function github_exchange_code($code) {
    if (!defined('CLIENT_ID') || CLIENT_ID === '') return null;
    $post = http_build_query([
        'client_id' => CLIENT_ID,
        'client_secret' => CLIENT_SECRET,
        'code' => $code,
        'redirect_uri' => CALLBACK_URL ?: current_url_base() . '/callback',
    ]);
    $opts = [
        'http' => [
            'method' => 'POST',
            'header' => "Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " . strlen($post) . "\r\n",
            'content' => $post,
            'timeout' => 10,
        ]
    ];
    $ctx = stream_context_create($opts);
    $res = @file_get_contents('https://github.com/login/oauth/access_token', false, $ctx);
    if ($res === false) return null;
    $json = json_decode($res, true);
    if (!$json || empty($json['access_token'])) return null;
    return $json['access_token'];
}

function github_get_user($token) {
    $opts = [
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Open-Geode-Index-PHP\r\nAuthorization: token " . $token . "\r\nAccept: application/json\r\n",
            'timeout' => 10
        ]
    ];
    $ctx = stream_context_create($opts);
    $res = @file_get_contents('https://api.github.com/user', false, $ctx);
    if ($res === false) return null;
    return json_decode($res, true);
}

function issue_local_tokens_for_user($username) {
    $tokens = db_read('tokens.json') ?: [];
    $access = bin2hex(random_bytes(20));
    $refresh = bin2hex(random_bytes(24));
    $now = time();
    $meta = [
        'username' => $username,
        'issued_at' => iso8601_utc($now),
        'expires_at' => iso8601_utc($now + ACCESS_TOKEN_TTL),
        'refresh_token' => $refresh,
        'refresh_expires_at' => iso8601_utc($now + REFRESH_TOKEN_TTL)
    ];
    $tokens[$access] = $meta;
    db_write('tokens.json', $tokens);
    return ['access_token' => $access, 'refresh_token' => $refresh];
}

function ensure_developer_record($username, $display = null) {
    $devs = db_read('developers.json') ?: [];
    foreach ($devs as $d) if (isset($d['username']) && $d['username'] === $username) return;
    $new = ['id' => time(), 'username' => $username, 'display_name' => $display ?: $username, 'verified' => false, 'admin' => false, 'github_id' => null];
    $devs[] = $new;
    db_write('developers.json', $devs);
}

function current_url_base() {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    return $scheme . '://' . $host;
}

function expand_gd_platforms($gd) {
    if (empty($gd)) return $gd;
    if (!is_array($gd)) return $gd; // leave strings unchanged

    $out = $gd; // copy original

    // Android -> android32 + android64
    if (isset($gd['android']) && $gd['android'] !== null && $gd['android'] !== '') {
        if (!isset($out['android32'])) $out['android32'] = $gd['android'];
        if (!isset($out['android64'])) $out['android64'] = $gd['android'];
    }

    // Mac -> mac-intel + mac-arm
    if (isset($gd['mac']) && $gd['mac'] !== null && $gd['mac'] !== '') {
        // create both common keys; note: user asked for "mac-inel" but "mac-intel" is typical — include both safe keys
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
    // expand gd platform keys for public consumption
    if (isset($out['gd'])) $out['gd'] = expand_gd_platforms($out['gd']);
    // prefer internal proxy link only when original download_link exists
    if (!empty($v['download_link'])) {
        $out['download_link'] = public_download_link($modid, $v['version']);
    } else {
        // attempt to fetch upstream mod/version and use its download_link
        $up = fetch_upstream_json("/v1/mods/{$modid}");
        if ($up && !empty($up['payload'])) {
            $upmod = $up['payload'];
            if (!empty($upmod['versions']) && is_array($upmod['versions'])) {
                foreach ($upmod['versions'] as $uv) {
                    if ((isset($uv['version']) && $uv['version'] === ($v['version'] ?? null)) || empty($v['version'])) {
                        if (!empty($uv['download_link'])) {
                            $out['download_link'] = $uv['download_link'];
                            break;
                        }
                    }
                }
            }
        }
        // if still empty, leave as empty string
        if (empty($out['download_link'])) $out['download_link'] = '';
    }
    return $out;
}

function mod_for_public($mod) {
    if (empty($mod) || !isset($mod['id'])) return $mod;
    $out = $mod;
    if (!empty($out['versions']) && is_array($out['versions'])) {
        $arr = [];
        foreach ($out['versions'] as $v) {
            $arr[] = version_for_public($out['id'], $v);
        }
        $out['versions'] = $arr;
    }
    return $out;
}

function fetch_upstream_json($path, $query = []) {
    // allow override via query param UPSTREAM_URL or header X-Upstream-Url for proxy mod
    $override = null;
    if (!empty($_GET['UPSTREAM_URL'])) $override = trim((string)$_GET['UPSTREAM_URL']);
    $hdrs = getallheaders_lower();
    if (empty($override) && !empty($hdrs['x-upstream-url'])) $override = trim((string)$hdrs['x-upstream-url']);

    $base = defined('UPSTREAM_URL') ? UPSTREAM_URL : 'https://api.geode-sdk.org';
    if (!empty($override)) {
        // basic validation: must start with http
        if (stripos($override, 'http') === 0) $base = rtrim($override, '/');
    }
    $url = $base . '/' . ltrim($path, '/');
    if (!empty($query)) $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($query);
    $opts = ['http' => ['method' => 'GET', 'header' => "User-Agent: Open-Geode-Index-PHP\r\nAccept: application/json\r\n", 'timeout' => 8]];
    $ctx = stream_context_create($opts);
    $res = @file_get_contents($url, false, $ctx);
    if ($res === false) return null;
    $j = json_decode($res, true);
    return $j ?: null;
}

function resolve_final_url($url, $max_redirects = 8, $timeout = 8) {
    if (empty($url)) return ['url' => null, 'code' => null];
    $current = $url;
    $redirects = 0;
    $opts = ['http' => ['method' => 'GET', 'header' => "User-Agent: Open-Geode-Index-PHP\r\nAccept: */*\r\n", 'timeout' => $timeout, 'ignore_errors' => true]];
    $ctx = stream_context_create($opts);
    while ($redirects <= $max_redirects) {
        $headers = @get_headers($current, 1, $ctx);
        if ($headers === false) return ['url' => null, 'code' => null];
        $statusLine = isset($headers[0]) ? (is_array($headers[0]) ? end($headers[0]) : $headers[0]) : null;
        $code = null;
        if ($statusLine && preg_match('/HTTP\/[\d\.]+\s+([0-9]{3})/i', $statusLine, $m)) $code = intval($m[1]);
        // If redirect with Location
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
            $current = $loc;
            $redirects++;
            continue;
        }
        // final status
        return ['url' => $current, 'code' => $code];
    }
    return ['url' => null, 'code' => null];
}

// "2024-02-19T21:58:33Z"
function iso8601_utc($ts = null) {
    if ($ts === null) $ts = time();
    return gmdate('Y-m-d\TH:i:s\Z', (int)$ts);
}

/* ======================= GitHub raw helpers ======================= */
function fetch_github_raw_json($repo, $path) {
    $url = "https://raw.githubusercontent.com/{$repo}/HEAD/{$path}";
    $opts = ['http' => ['method' => 'GET', 'header' => "User-Agent: Open-Geode-Index-PHP\r\nAccept: application/json\r\n", 'timeout' => 8]];
    $ctx = stream_context_create($opts);
    $res = @file_get_contents($url, false, $ctx);
    if ($res === false) return null;
    $j = json_decode($res, true);
    if (!$j) return null;
    return $j;
}
function fetch_github_raw_text($repo, $path) {
    $url = "https://raw.githubusercontent.com/{$repo}/HEAD/{$path}";
    $opts = ['http' => ['method' => 'GET', 'header' => "User-Agent: Open-Geode-Index-PHP\r\nAccept: text/plain\r\n", 'timeout' => 8]];
    $ctx = stream_context_create($opts);
    $res = @file_get_contents($url, false, $ctx);
    if ($res === false) return null;
    return $res;
}

/* ======================= API: tags ======================= */
function api_tags_index() {
    $tags = db_read('tags.json') ?: [];
    $names = [];
    foreach ($tags as $t) $names[] = is_array($t) && isset($t['name']) ? $t['name'] : (string)$t;
    json_response(['error' => '', 'payload' => $names]);
}
function api_tags_detailed() {
    $tags = db_read('tags.json') ?: [];
    json_response(['error' => '', 'payload' => $tags]);
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
    $per_page = isset($q['per_page']) ? max(1, intval($q['per_page'])) : 50;
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
            if (isset($body['admin'])) $devs[$i]['admin'] = (bool)$body['admin'];
            if (isset($body['verified'])) $devs[$i]['verified'] = (bool)$body['verified'];
            db_write('developers.json', $devs);
            return json_response(['error' => '', 'payload' => $devs[$i]]);
        }
    }
    json_response(['error' => 'Developer not found', 'payload' => null], 404);
}

/* ======================= API: auth ======================= */
function api_login_github() {
    // Start web OAuth device - return URL in payload
    $state = bin2hex(random_bytes(12));
    $_SESSION['oauth_state'] = $state;
    $redirect = CALLBACK_URL ?: current_url_base() . '/callback';
    $params = http_build_query(['client_id' => CLIENT_ID, 'redirect_uri' => $redirect, 'scope' => 'read:user', 'state' => $state]);
    $url = "https://github.com/login/oauth/authorize?$params";
    json_response(['error' => '', 'payload' => $url]);
}
function api_login_github_web() {
    return api_login_github();
}
function api_login_callback() {
    $body = json_input() ?: $_REQUEST;
    if (empty($body['code']) || empty($body['state'])) return json_response(['error' => 'bad request', 'payload' => null], 400);
    $code = $body['code']; $state = $body['state'];
    if (!isset($_SESSION['oauth_state']) || $_SESSION['oauth_state'] !== $state) return json_response(['error' => 'invalid state', 'payload' => null], 400);
    $token = github_exchange_code($code);
    if (!$token) return json_response(['error' => 'failed to obtain access token', 'payload' => null], 400);
    $user = github_get_user($token);
    if (!$user || empty($user['login'])) return json_response(['error' => 'failed to fetch GitHub user', 'payload' => null], 400);
    $_SESSION['github_user'] = $user['login'];
    $_SESSION['github_token'] = $token;
    ensure_developer_record($user['login'], $user['name'] ?? $user['login']);
    $local = issue_local_tokens_for_user($user['login']);
    json_response(['error' => '', 'payload' => $local]);
}
function api_login_github_poll() {
    json_response(['error' => 'not implemented', 'payload' => null], 501);
}
function api_login_github_token() {
    $body = json_input();
    if (!$body || empty($body['token'])) return json_response(['error' => 'bad request', 'payload' => null], 400);
    $pat = $body['token'];
    $user = github_get_user($pat);
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
    foreach ($devs as $d) if (isset($d['username']) && $d['username'] === $u) return json_response(['error' => '', 'payload' => $d]);
    json_response(['error' => '', 'payload' => ['id' => null, 'username' => $u, 'display_name' => $u, 'verified' => false, 'admin' => is_admin(), 'github_id' => null]]);
}
function api_put_me() {
    if (!require_auth()) return;
    $u = current_user();
    $body = json_input();
    if (!$body) return json_response(['error' => 'bad request', 'payload' => null], 400);
    $devs = db_read('developers.json') ?: [];
    foreach ($devs as $i => $d) {
        if (isset($d['username']) && $d['username'] === $u) {
            if (isset($body['display_name'])) $devs[$i]['display_name'] = $body['display_name'];
            db_write('developers.json', $devs);
            return json_response(['error' => '', 'payload' => $devs[$i]]);
        }
    }
    $new = ['id' => time(), 'username' => $u, 'display_name' => $body['display_name'] ?? $u, 'verified' => false, 'admin' => false, 'github_id' => null];
    $devs[] = $new;
    db_write('developers.json', $devs);
    return json_response(['error' => '', 'payload' => $new]);
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
        $token = $m[1];
        $tokens = db_read('tokens.json') ?: [];
        if (isset($tokens[$token])) { unset($tokens[$token]); db_write('tokens.json', $tokens); return json_response(['error' => '', 'payload' => null], 204); }
        return json_response(['error' => 'not found', 'payload' => null], 404);
    }
    return json_response(['error' => '', 'payload' => null], 204);
}
function api_delete_tokens() {
    if (!require_auth()) return;
    $u = current_user();
    $tokens = db_read('tokens.json') ?: [];
    foreach ($tokens as $k => $meta) {
        if (!empty($meta['username']) && $meta['username'] === $u) unset($tokens[$k]);
    }
    db_write('tokens.json', $tokens);
    return json_response(['error' => '', 'payload' => null], 204);
}

/* ======================= API: loader versions ======================= */
function api_loader_versions_index() {
    $q = $_GET;
    $all = db_read('loader_versions.json') ?: [];
    if (isset($q['prerelease'])) {
        $pr = filter_var($q['prerelease'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($pr !== null) $all = array_values(array_filter($all, function ($v) use ($pr) { return !empty($v['prerelease']) === $pr; }));
    }
    if (!empty($q['gd'])) {
        $gd = (string)$q['gd'];
        $all = array_values(array_filter($all, function ($v) use ($gd) { return !empty($v['gd']) && (is_string($v['gd']) ? strpos($v['gd'], $gd) !== false : true); }));
    }
    $page = isset($q['page']) ? max(1, intval($q['page'])) : 1;
    $per_page = isset($q['per_page']) ? max(1, intval($q['per_page'])) : 50;
    $count = count($all);
    $data = array_slice($all, ($page - 1) * $per_page, $per_page);
    json_response(['error' => '', 'payload' => ['data' => $data, 'count' => $count]]);
}
function api_loader_versions_create() {
    if (!require_admin()) return;
    $body = json_input();
    if (!$body || empty($body['tag']) || empty($body['commit_hash']) || empty($body['gd'])) return json_response(['error' => 'bad request', 'payload' => null], 400);
    $all = db_read('loader_versions.json') ?: [];
    $v = ['version' => $body['tag'], 'tag' => $body['tag'], 'gd' => $body['gd'], 'prerelease' => !empty($body['prerelease']), 'commit_hash' => $body['commit_hash'], 'created_at' => iso8601_utc()];
    array_unshift($all, $v);
    db_write('loader_versions.json', $all);
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

    // filtering: query, tags, featured (existing behavior)
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
        if ($f !== null) $mods = array_values(array_filter($mods, function ($m) use ($f) { return !empty($m['featured']) === $f; }));
    }

    // sorting
    $sort = isset($q['sort']) ? (string)$q['sort'] : 'downloads';
    // normalize date helper
    $ts = function($d) {
        if (empty($d)) return 0;
        $t = @strtotime($d);
        return $t === false ? 0 : $t;
    };

    usort($mods, function($a, $b) use ($sort, $ts) {
        // helper tiebreaker: updated_at desc, id asc
        $tiebreak = function($x, $y) use ($ts) {
            $ux = $ts($x['updated_at'] ?? null);
            $uy = $ts($y['updated_at'] ?? null);
            if ($ux !== $uy) return $uy <=> $ux ? $uy <=> $ux : 0; // want desc
            $ida = strtolower($x['id'] ?? '');
            $idb = strtolower($y['id'] ?? '');
            return $ida <=> $idb;
        };

        switch ($sort) {
            case 'recently_updated':
                $a_t = $ts($a['updated_at'] ?? null);
                $b_t = $ts($b['updated_at'] ?? null);
                if ($a_t === $b_t) return $tiebreak($a, $b);
                return $b_t <=> $a_t; // desc
            case 'recently_published':
                $a_t = $ts($a['created_at'] ?? null);
                $b_t = $ts($b['created_at'] ?? null);
                if ($a_t === $b_t) return $tiebreak($a, $b);
                return $b_t <=> $a_t; // desc
            case 'oldest':
                $a_t = $ts($a['created_at'] ?? null);
                $b_t = $ts($b['created_at'] ?? null);
                if ($a_t === $b_t) return $tiebreak($a, $b);
                return $a_t <=> $b_t; // asc
            case 'name':
                $na = strtolower($a['id'] ?? '');
                $nb = strtolower($b['id'] ?? '');
                if ($na === $nb) return $tiebreak($a, $b);
                return $na <=> $nb;
            case 'name_reverse':
                $na = strtolower($a['id'] ?? '');
                $nb = strtolower($b['id'] ?? '');
                if ($na === $nb) return $tiebreak($a, $b);
                return $nb <=> $na;
            case 'downloads':
            default:
                // downloads descending; fallback to mod.download_count or sum of version download_count
                $da = isset($a['download_count']) ? (int)$a['download_count'] : 0;
                $db = isset($b['download_count']) ? (int)$b['download_count'] : 0;
                if ($da === $db) return $tiebreak($a, $b);
                return $db <=> $da; // desc
        }
    });

    // pagination
    $page = isset($q['page']) ? max(1, intval($q['page'])) : 1;
    $per_page = isset($q['per_page']) ? max(1, intval($q['per_page'])) : 50;
    $count = count($mods);
    $slice = array_slice($mods, ($page - 1) * $per_page, $per_page);

    // return public versions (keep behavior: versions replaced with internal public download link)
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

    // optional repo still allowed for reference, but metadata MUST come from .geode
    $repo = !empty($body['repo']) ? trim($body['repo']) : null;

    // extract metadata from .geode (required)
    $meta = extract_metadata_from_geode($body['download_link']);
    if ($meta === null || empty($meta['modjson'])) {
        return json_response(['error' => 'bad request - mod.json not found inside .geode (metadata must come from archive)', 'payload' => null], 400);
    }
    $modjson = $meta['modjson'];

    // build canonical id from mod.json (fallback to repo if absent)
    $mod_id = !empty($modjson['id']) ? (string)$modjson['id'] : ($repo ?: null);
    if (empty($mod_id)) return json_response(['error' => 'bad request - cannot determine mod id', 'payload' => null], 400);

    $mod_name = !empty($modjson['name']) ? (string)$modjson['name'] : $mod_id;
    $mod_tags = !empty($modjson['tags']) && is_array($modjson['tags']) ? $modjson['tags'] : [];
    $mod_about = !empty($meta['about']) ? $meta['about'] : null;
    $changelog = !empty($meta['changelog']) ? $meta['changelog'] : null;

    $initial_version = isset($body['version']) ? $body['version'] : (isset($modjson['version']) ? $modjson['version'] : null);
    $initial_version = normalize_version($initial_version) ?: '1.0.0';

    $featured = false;
    if (!empty($body['featured']) && is_admin()) $featured = (bool)$body['featured'];

    // gd/geode from mod.json if present
    $geode_val = isset($modjson['geode']) ? normalize_geode($modjson['geode']) : null;
    $gd_val = isset($modjson['gd']) && is_array($modjson['gd']) ? normalize_gd($modjson['gd']) : null;

    $mods = db_read('mods.json') ?: [];
    // reject duplicates by id
    foreach ($mods as $m) if (isset($m['id']) && $m['id'] === $mod_id) return json_response(['error' => 'mod already exists (by id)', 'payload' => null], 409);

    // compute hash
    $hash_val = compute_remote_sha256($body['download_link']);
    if ($hash_val === null) return json_response(['error' => 'bad request - can\'t get sha256 from download_link', 'payload' => null], 400);

    $now = iso8601_utc();
    $version_entry = [
        'name' => $mod_name,
        'version' => $initial_version,
        'download_link' => $body['download_link'],
        'hash' => $hash_val,
        'geode' => $geode_val,
        'download_count' => 0,
        'early_load' => !empty($body['early_load']),
        'requires_patching' => !empty($body['requires_patching']),
        'api' => !empty($body['api']),
        'mod_id' => $mod_id,
        'gd' => expand_gd_platforms($gd_val),
        'status' => 'accepted',
        'description' => isset($modjson['description']) ? $modjson['description'] : null,
        'created_at' => $now,
        'updated_at' => $now,
    ];

    $repository_url = $repo ? "https://github.com/{$repo}" : null;
    $logo_url = !empty($modjson['logo_url']) ? $modjson['logo_url'] : ($repo ? "https://raw.githubusercontent.com/{$repo}/HEAD/logo.png" : null);

    $devs = [];
    if (!empty($modjson['developers'])) $devs = map_modjson_developers($modjson['developers'], $u);
    else $devs = map_modjson_developers([], $u);

    $mod = [
        'id' => $mod_id,
        'about' => $mod_about,
        'changelog' => $changelog,
        'created_at' => $now,
        'updated_at' => $now,
        'developers' => $devs,
        'download_count' => 0,
        'featured' => $featured,
        'tags' => $mod_tags,
        'versions' => [$version_entry],
        'repo' => $repo,
        'repository' => $repository_url,
        'logo_url' => $logo_url,
        'links' => isset($modjson['links']) && is_array($modjson['links']) ? $modjson['links'] : null,
        'submitted_by' => $u,
    ];
    
    $mods[] = $mod;
    db_write('mods.json', $mods);
    json_response(['error' => '', 'payload' => mod_for_public($mod)], 201);
}

function api_mods_get($id) {
    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $m) {
        if ($m['id'] === $id) return json_response(['error' => '', 'payload' => mod_for_public($m)]);
    }

    // fallback to upstream
    if (defined('UPSTREAM_API') && UPSTREAM_API) {
        $up = fetch_upstream_json("/v1/mods/" . rawurlencode($id));
        if ($up && isset($up['error']) && $up['error'] === '' && !empty($up['payload'])) {
            return json_response(['error' => '', 'payload' => $up['payload']]);
        }
        // propagate upstream 404 as local 404
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
            if (isset($body['about'])) $mods[$i]['about'] = $body['about'];
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
        if ($m['id'] === $id) {
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

            // allow owner/admin to update owner's display_name
            if (isset($body['owner_display_name'])) {
                $newname = trim((string)$body['owner_display_name']);
                if ($newname !== '') {
                    $updated = false;
                    // prefer explicit is_owner flag
                    if (!empty($mods[$i]['developers']) && is_array($mods[$i]['developers'])) {
                        foreach ($mods[$i]['developers'] as $di => $dev) {
                            if (!empty($dev['is_owner'])) {
                                $mods[$i]['developers'][$di]['display_name'] = $newname;
                                $updated = true;
                                break;
                            }
                        }
                        // fallback to first developer if no is_owner found
                        if (!$updated && count($mods[$i]['developers']) > 0) {
                            $mods[$i]['developers'][0]['display_name'] = $newname;
                            $updated = true;
                        }
                    }
                    if ($updated) {
                        // update mod updated_at (will be written later when db_write is called)
                        $mods[$i]['updated_at'] = iso8601_utc();
                    }
                }
            }

            if (isset($body['prefer_github_info'])) $mods[$i]['prefer_github_info'] = (bool)$body['prefer_github_info'];

            if (!empty($body['download_link'])) {
                $meta = extract_metadata_from_geode($body['download_link']);
                if ($meta === null || empty($meta['modjson'])) {
                    return json_response(['error' => 'bad request - mod.json not found inside .geode', 'payload' => null], 400);
                }
                $inner = $meta['modjson'];

                if (!empty($inner['id']) && $inner['id'] !== $mods[$i]['id']) {
                    return json_response(['error' => 'bad request - mod id inside .geode does not match existing mod id', 'payload' => null], 400);
                }

                $ver_raw = $body['version'] ?? ($inner['version'] ?? null);
                $ver = normalize_version($ver_raw) ?: ($ver_raw ?: null);
                if ($ver === null) {
                    $ver = date('YmdHis');
                }

                $now = iso8601_utc();
                $hash_val = compute_remote_sha256($body['download_link']);
                if ($hash_val === null) return json_response(['error' => 'bad request - can\'t get sha256 from download_link', 'payload' => null], 400);

                $newver = [
                    'name' => isset($inner['name']) ? $inner['name'] : (isset($body['name']) ? $body['name'] : ($mods[$i]['repo'] ?? $mods[$i]['id'])),
                    'version' => $ver,
                    'download_link' => $body['download_link'],
                    'hash' => $hash_val,
                    'geode' => isset($inner['geode']) ? normalize_geode($inner['geode']) : (isset($body['geode']) ? normalize_geode($body['geode']) : null),
                    'download_count' => 0,
                    'early_load' => !empty($body['early_load']),
                    'requires_patching' => !empty($body['requires_patching']),
                    'api' => !empty($inner['api']) ? (bool)$inner['api'] : !empty($body['api']),
                    'mod_id' => $mods[$i]['id'],
                    'gd' => isset($inner['gd']) ? normalize_gd($inner['gd']) : (isset($body['gd']) && is_array($body['gd']) ? normalize_gd($body['gd']) : null),
                    'status' => 'accepted',
                    'description' => isset($inner['description']) ? $inner['description'] : (isset($body['description']) ? $body['description'] : (!empty($meta['about']) ? mb_strimwidth($meta['about'], 0, 1000, '...') : null)),
                    'created_at' => $now,
                    'updated_at' => $now,
                ];

                $replaced = false;
                foreach ($mods[$i]['versions'] as $vi => $vv) {
                    if ($vv['version'] === $newver['version']) {
                        $mods[$i]['versions'][$vi] = $newver;
                        $replaced = true;
                        break;
                    }
                }
                if (!$replaced) array_unshift($mods[$i]['versions'], $newver);

                if (!empty($meta['about'])) $mods[$i]['about'] = $meta['about'];
                if (!empty($meta['changelog'])) $mods[$i]['changelog'] = $meta['changelog'];

                $mods[$i]['updated_at'] = iso8601_utc();
                db_write('mods.json', $mods);
                return json_response(['error' => '', 'payload' => $mods[$i]], 200);
            }

            if (isset($body['links']) && is_array($body['links'])) $mods[$i]['links'] = $body['links'];

            if (!empty($mods[$i]['versions'][0]['download_link'])) {
                $meta2 = extract_metadata_from_geode($mods[$i]['versions'][0]['download_link']);
                if ($meta2 !== null) {
                    if (!empty($meta2['about'])) $mods[$i]['about'] = $meta2['about'];
                    if (!empty($meta2['changelog'])) $mods[$i]['changelog'] = $meta2['changelog'];
                }
            }

            $mods[$i]['updated_at'] = iso8601_utc();
            db_write('mods.json', $mods);
            return json_response(['error' => '', 'payload' => $mods[$i]], 200);
        }
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mods_delete($id) {
    // allow admin or owner
    if (!require_auth()) return;
    $u = current_user();
    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if ($m['id'] === $id) {
            $allowed = is_admin();
            if (!$allowed) {
                // check owners
                foreach ($m['developers'] as $d) {
                    if (!empty($d['username']) && $d['username'] === $u && !empty($d['is_owner'])) {
                        $allowed = true;
                        break;
                    }
                }
            }
            if (!$allowed) return json_response(['error' => 'forbidden - only owner or admin can delete', 'payload' => null], 403);

            // remove mod
            array_splice($mods, $i, 1);
            db_write('mods.json', $mods);

            // remove related deprecations (cleanup)
            $deprec = db_read('deprecations.json') ?: [];
            $deprec = array_values(array_filter($deprec, function ($d) use ($id) { return !isset($d['mod_id']) || $d['mod_id'] !== $id; }));
            db_write('deprecations.json', $deprec);

            return json_response(['error' => '', 'payload' => null], 204);
        }
    }
    return json_response(['error' => 'mod not found', 'payload' => null], 404);
}
function api_mods_updates() {
    $q = $_GET;
    if (empty($q['ids'])) return json_response(['error' => 'bad request - ids required', 'payload' => null], 400);

    $up = fetch_upstream_json('/v1/mods/updates', $q);
    $up_payload = ['deprecations' => [], 'updates' => []];
    if ($up && isset($up['error']) && $up['error'] === '' && isset($up['payload'])) {
        $up_payload = $up['payload'];
        if (!isset($up_payload['deprecations'])) $up_payload['deprecations'] = [];
        if (!isset($up_payload['updates'])) $up_payload['updates'] = [];
    }

    $raw = (string)$q['ids'];
    $ids = array_values(array_filter(array_map('trim', preg_split('/[;,]+/', $raw))));
    $client_geode = isset($q['geode']) ? (string)$q['geode'] : null;
    $client_gd = isset($q['gd']) ? (string)$q['gd'] : null;
    $platform = isset($q['platform']) ? (string)$q['platform'] : (isset($q['platforms']) ? (string)$q['platforms'] : null);

    $mods = db_read('mods.json') ?: [];
    $deprec = db_read('deprecations.json') ?: [];

    $mods_index = [];
    foreach ($mods as $m) if (!empty($m['id'])) $mods_index[$m['id']] = $m;

    $local_deprec = array_values(array_filter($deprec, function ($d) use ($ids) {
        return isset($d['mod_id']) && in_array($d['mod_id'], $ids);
    }));

    $local_updates = [];
    foreach ($ids as $id) {
        if (!isset($mods_index[$id])) continue;
        $mod = $mods_index[$id];

        $chosen = null;
        if (!empty($mod['versions']) && is_array($mod['versions'])) {
            foreach ($mod['versions'] as $v) {
                if (!empty($v['status']) && strtolower($v['status']) !== 'accepted') continue;

                $v_geode = isset($v['geode']) ? normalize_geode($v['geode']) : null;
                if ($v_geode !== null && $client_geode !== null) {
                    if (version_compare($v_geode, $client_geode, '>')) continue;
                }

                $v_gd = isset($v['gd']) ? $v['gd'] : null;
                if (!empty($client_gd) && !empty($v_gd) && is_array($v_gd)) {
                    $compatible_gd = true;
                    if ($platform) {
                        if (isset($v_gd[$platform])) {
                            $req = (string)$v_gd[$platform];
                            if ($req !== '*' && $req !== '') {
                                if (version_compare($req, $client_gd, '>')) $compatible_gd = false;
                            }
                        }
                    } else {
                        foreach ($v_gd as $req) {
                            if ($req === '*' || $req === '') continue;
                            if (!empty($client_gd) && version_compare((string)$req, $client_gd, '>')) { $compatible_gd = false; break; }
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
            'id' => $mod['id'],
            'version' => $chosen['version'] ?? '',
            'download_link' => $chosen['download_link'] ?? '',
            'dependencies' => isset($chosen['dependencies']) && is_array($chosen['dependencies']) ? $chosen['dependencies'] : [],
            'incompatibilities' => isset($chosen['incompatibilities']) && is_array($chosen['incompatibilities']) ? $chosen['incompatibilities'] : [],
            'gd' => isset($chosen['gd']) ? (is_array($chosen['gd']) ? $chosen['gd'] : null) : null,
            'replacement' => null
        ];
    }

    $merged_updates = [];
    $up_index = [];
    foreach ($up_payload['updates'] as $u) if (!empty($u['id'])) $up_index[$u['id']] = $u;
    
    foreach ($up_payload['updates'] as $u) $merged_updates[$u['id']] = $u;
    foreach ($local_updates as $lu) $merged_updates[$lu['id']] = $lu; // overwrites if present
    
    $final_updates = [];

    foreach ($up_payload['updates'] as $u) {
        if (isset($merged_updates[$u['id']])) {
            $final_updates[] = $merged_updates[$u['id']];
            unset($merged_updates[$u['id']]);
        }
    }
    
    foreach ($merged_updates as $rem) $final_updates[] = $rem;

    $all_deprec = array_merge($up_payload['deprecations'], $local_deprec);
    $seen = [];
    $final_deprec = [];
    foreach ($all_deprec as $d) {
        $key = (isset($d['mod_id']) ? $d['mod_id'] : '') . '|' . (isset($d['id']) ? $d['id'] : md5(json_encode($d)));
        if (isset($seen[$key])) continue;
        $seen[$key] = true;
        $final_deprec[] = $d;
    }

    json_response(['error' => '', 'payload' => ['deprecations' => $final_deprec, 'updates' => array_values($final_updates)]], 200);
}

/* ======================= API: deprecations ======================= */
function api_deprecations_index($modid) {
    $deprec = db_read('deprecations.json') ?: [];
    $out = array_values(array_filter($deprec, function ($d) use ($modid) { return isset($d['mod_id']) && $d['mod_id'] === $modid; }));
    json_response(['error' => '', 'payload' => $out]);
}
function api_deprecations_create($modid) {
    if (!require_auth()) return;
    $body = json_input();
    if (!$body || empty($body['by']) || empty($body['reason'])) return json_response(['error' => 'bad request', 'payload' => null], 400);
    $deprec = db_read('deprecations.json') ?: [];
    $id = time();
    $row = ['id' => $id, 'mod_id' => $modid, 'by' => $body['by'], 'reason' => $body['reason']];
    $deprec[] = $row;
    db_write('deprecations.json', $deprec);
    json_response(['error' => '', 'payload' => $row], 201);
}
function api_deprecations_clear_all($modid) {
    if (!require_admin()) return;
    $deprec = db_read('deprecations.json') ?: [];
    $deprec = array_values(array_filter($deprec, function ($d) use ($modid) { return !isset($d['mod_id']) || $d['mod_id'] !== $modid; }));
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
            if (isset($body['by'])) $deprec[$i]['by'] = $body['by'];
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
        if ($d['id'] === $depid && $d['mod_id'] === $modid) { array_splice($deprec, $i, 1); db_write('deprecations.json', $deprec); return json_response(['error' => '', 'payload' => null], 204); }
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
        if ($m['id'] === $modid) {
            $u = current_user(); $allowed = is_admin();
            if (!$allowed) {
                foreach ($m['developers'] as $d) if (!empty($d['username']) && $d['username'] === $u && !empty($d['is_owner'])) { $allowed = true; break; }
            }
            if (!$allowed) return json_response(['error' => 'forbidden', 'payload' => null], 403);
            $mods[$i]['developers'][] = ['id' => null, 'username' => $body['username'], 'display_name' => $body['username'], 'is_owner' => !empty($body['is_owner'])];
            db_write('mods.json', $mods);
            return json_response(['error' => '', 'payload' => null], 204);
        }
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

function api_mod_remove_developer($modid, $username) {
    if (!require_auth()) return;
    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if ($m['id'] === $modid) {
            $u = current_user(); $allowed = is_admin();
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

    if (defined('UPSTREAM_API') && UPSTREAM_API) {
        $url = UPSTREAM_API . '/v1/mods/' . rawurlencode($modid) . '/logo';
        if (@file_get_contents($url)) {
            header('Location: '.$url); exit(); 
        }
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
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}
function api_mod_versions_create($modid) {
    if (!require_auth()) return;
    $body = json_input();
    if (!$body || empty($body['version']) || empty($body['download_link'])) return json_response(['error' => 'bad request', 'payload' => null], 400);
    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if ($m['id'] === $modid) {
            $u = current_user(); $allowed = is_admin();
            if (!$allowed) {
                foreach ($m['developers'] as $d) if (!empty($d['username']) && $d['username'] === $u && !empty($d['is_owner'])) { $allowed = true; break; }
            }
            if (!$allowed) return json_response(['error' => 'forbidden', 'payload' => null], 403);

            // extract metadata from .geode (required)
            $meta = extract_metadata_from_geode($body['download_link']);
            if ($meta === null || empty($meta['modjson'])) {
                return json_response(['error' => 'bad request - mod.json not found inside .geode', 'payload' => null], 400);
            }
            $inner = $meta['modjson'];
            if (!empty($inner['id']) && $inner['id'] !== $modid) {
                return json_response(['error' => 'bad request - mod id inside .geode does not match mod id', 'payload' => null], 400);
            }

            $ver = normalize_version($body['version']) ?: $body['version'];
            $now = iso8601_utc();
            $hash_val = compute_remote_sha256($body['download_link']);
            if ($hash_val === null) return json_response(['error' => 'bad request - can\'t get sha256 from download_link', 'payload' => null], 400);;

            $newver = [
                'name' => isset($inner['name']) ? $inner['name'] : (isset($body['name']) ? $body['name'] : $modid),
                'version' => $ver,
                'download_link' => $body['download_link'],
                'hash' => $hash_val,
                'geode' => isset($inner['geode']) ? normalize_geode($inner['geode']) : (isset($body['geode']) ? normalize_geode($body['geode']) : null),
                'download_count' => 0,
                'early_load' => !empty($body['early_load']),
                'requires_patching' => !empty($body['requires_patching']),
                'api' => !empty($inner['api']) ? (bool)$inner['api'] : !empty($body['api']),
                'mod_id' => $m['id'],
                'gd' => isset($inner['gd']) ? normalize_gd($inner['gd']) : (isset($body['gd']) && is_array($body['gd']) ? normalize_gd($body['gd']) : null),
                'status' => 'accepted',
                'description' => isset($inner['description']) ? $inner['description'] : (!empty($meta['about']) ? mb_strimwidth($meta['about'], 0, 1000, '...') : null),
                'created_at' => $now,
                'updated_at' => $now,
            ];
            array_unshift($mods[$i]['versions'], $newver);
            // refresh mod-level about/changelog from archive if present
            if (!empty($meta['about'])) $mods[$i]['about'] = $meta['about'];
            if (!empty($meta['changelog'])) $mods[$i]['changelog'] = $meta['changelog'];
            $mods[$i]['updated_at'] = iso8601_utc();
            db_write('mods.json', $mods);            array_unshift($mods[$i]['versions'], $newver);
            db_write('mods.json', $mods);
            return json_response(['error' => '', 'payload' => version_for_public($mods[$i]['id'], $newver)], 201);
            return json_response(['error' => '', 'payload' => $newver], 201);
        }
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}
function api_mod_versions_get($modid, $version) {
    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $m) {
        if ($m['id'] === $modid) {
            foreach ($m['versions'] as $v) {
                if ($v['version'] === $version) return json_response(['error' => '', 'payload' => version_for_public($m['id'], $v)]);
            }
            return json_response(['error' => 'version not found', 'payload' => null], 404);
        }
    }

    // fallback to upstream
    if (defined('UPSTREAM_API') && UPSTREAM_API) {
        $up = fetch_upstream_json("/v1/mods/" . rawurlencode($modid) . "/versions/" . rawurlencode($version));
        if ($up && isset($up['error']) && $up['error'] === '' && !empty($up['payload'])) {
            // upstream already returns a version object; return it as-is
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
        if ($m['id'] === $modid) {
            foreach ($m['versions'] as $j => $v) {
                if ($v['version'] === $version) {
                    // update simple fields
                    if (isset($body['status'])) $mods[$i]['versions'][$j]['status'] = $body['status'];
                    if (isset($body['info'])) $mods[$i]['versions'][$j]['info'] = $body['info'];

                    // download_link/hash handling: only when download_link provided
                    if (!empty($body['download_link'])) {
                        $new_download = trim($body['download_link']);
                        $mods[$i]['versions'][$j]['download_link'] = $new_download;
                        $mods[$i]['versions'][$j]['hash'] = compute_remote_sha256($new_download);
                        // set created_at only if it's a brand-new version — here we are updating, so update updated_at below
                    }

                    // one updated_at assign
                    $mods[$i]['versions'][$j]['updated_at'] = iso8601_utc();
                    $mods[$i]['updated_at'] = iso8601_utc();
                    db_write('mods.json', $mods);
                    return json_response(['error' => '', 'payload' => $mods[$i]['versions'][$j]], 200);
                }
            }
            return json_response(['error' => 'version not found', 'payload' => null], 404);
        }
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mod_versions_download($modid, $version) {
    $mods = db_read('mods.json') ?: [];
    // find local mod/version
    foreach ($mods as $i => $m) {
        if ($m['id'] === $modid) {
            foreach ($m['versions'] as $j => $v) {
                if ($v['version'] === $version) {
                    // increment counters (use local counters even if we fallback to upstream URL)
                    $mods[$i]['versions'][$j]['download_count'] = ($mods[$i]['versions'][$j]['download_count'] ?? 0) + 1;
                    $mods[$i]['download_count'] = ($mods[$i]['download_count'] ?? 0) + 1;
                    db_write('mods.json', $mods);

                    $local_link = !empty($v['download_link']) ? $v['download_link'] : null;

                    // if local_link present -> verify reachable and follow redirects; else try upstream
                    if ($local_link) {
                        $res = resolve_final_url($local_link);
                        if (!empty($res['url']) && $res['code'] !== null && $res['code'] >= 200 && $res['code'] < 400) {
                            header('Location: ' . $res['url'], true, 302);
                            exit;
                        }
                        // local link unreachable — try upstream fallback
                    }

                    // fallback: ask upstream for this mod/version
                    $up = fetch_upstream_json("/v1/mods/{$modid}/versions/{$version}");
                    if ($up && isset($up['error']) && $up['error'] === '' && !empty($up['payload'])) {
                        $uv = $up['payload'];
                        $up_link = !empty($uv['download_link']) ? $uv['download_link'] : null;
                        if ($up_link) {
                            $res2 = resolve_final_url($up_link);
                            if (!empty($res2['url']) && $res2['code'] !== null && $res2['code'] >= 200 && $res2['code'] < 400) {
                                header('Location: ' . $res2['url'], true, 302);
                                exit;
                            }
                        }
                    }

                    // if we reach here, try raw local link (may still redirect) or respond error
                    if ($local_link) {
                        header('Location: ' . $local_link, true, 302);
                        exit;
                    }

                    return json_response(['error' => 'version download link not available', 'payload' => null], 502);
                }
            }
            return json_response(['error' => 'version not found', 'payload' => null], 404);
        }
    }

    // not found locally — try upstream updates / specific version
    $upv = fetch_upstream_json("/v1/mods/{$modid}/versions/{$version}");
    if ($upv && isset($upv['error']) && $upv['error'] === '' && !empty($upv['payload'])) {
        $uv = $upv['payload'];
        $up_link = !empty($uv['download_link']) ? $uv['download_link'] : null;
        if ($up_link) {
            $res2 = resolve_final_url($up_link);
            if (!empty($res2['url']) && $res2['code'] !== null && $res2['code'] >= 200 && $res2['code'] < 400) {
                // increment nothing locally (mod not present), just redirect
                header('Location: ' . $res2['url'], true, 302);
                exit;
            } else {
                header('Location: ' . $up_link, true, 302);
                exit;
            }
        }
    }

    // final fallback
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

/* ======================= API: stats ======================= */
function api_stats() {
    $mods = db_read('mods.json') ?: [];
    $devs = db_read('developers.json') ?: [];
    $total_mod_count = count($mods);
    $total_mod_downloads = 0;
    $total_geode_downloads = 0;
    foreach ($mods as $m) $total_mod_downloads += ($m['download_count'] ?? 0);
    json_response(['error' => '', 'payload' => ['total_geode_downloads' => $total_geode_downloads, 'total_mod_count' => $total_mod_count, 'total_mod_downloads' => $total_mod_downloads, 'total_registered_developers' => count($devs)]]);
}

/* ======================= UI renderers ======================= */
function handle_home() { header('Location: /ui'); exit; }

function asAPIReqForm() { return ("
<script>
document.querySelector('form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    let a = this.querySelector('button[type=\"submit\"]');
    if (!a) a = this.querySelector('button');
    
    a.parentElement.className += ' disabled placeholder-glow';
    a.parentElement.style.opacity = '0.5';
    a.className += ' disabled placeholder';
    a.disabled = true;

    let formData = new FormData(this);

    fetch(this.action, {
        method: this.method,
        body: formData
    })
    .then(async response => {
        let data;
        try { data = await response.json(); } 
        catch (e) { throw new Error('Invalid JSON'); }
        
        if (!response.ok) { 
            let errorMsg = data.error || 'Server error (HTTP ' + response.status + ')';
            throw new Error(errorMsg);
        }
        return data;
    })
    .then(data => {
        if (data.error && data.error.trim() !== '') {
            alert('Error: ' + data.error);
            a.parentElement.className = a.parentElement.className.replace(/ disabled placeholder-glow/g, '').trim();
            a.parentElement.style.opacity = '1';
            a.className = a.className.replace(/ disabled placeholder/g, '').trim();
            a.disabled = false;
        } else {
            alert('Request successful :D');
            window.location.reload();
        }
    })
    .catch(error => {
        alert('Error: ' + error.message);
        a.parentElement.className = a.parentElement.className.replace(/ disabled placeholder-glow/g, '').trim();
        a.parentElement.style.opacity = '1';
        a.className = a.className.replace(/ disabled placeholder/g, '').trim();
        a.disabled = false;
    });
});
</script>
"); }

function ui_header($title = 'Main') {
    $user = current_user();
    $is_admin = is_admin();

    // Meta values
    $site_title = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $description = htmlspecialchars(SITE_DESCRIPTION, ENT_QUOTES, 'UTF-8');
    $current_url = htmlspecialchars(current_url_base() . $_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8');
    $icon = ICON_URL;
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

  <meta property="og:title" content="<?php echo $site_title; ?>">
  <meta property="og:description" content="<?php echo $description; ?>">
  <meta property="og:image" content="<?php echo htmlspecialchars($icon, ENT_QUOTES, 'UTF-8'); ?>">
  <meta property="og:type" content="website">
  <meta property="og:url" content="<?php echo $current_url; ?>">

  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="<?php echo $site_title; ?>">
  <meta name="twitter:description" content="<?php echo $description; ?>">
  <meta name="twitter:image" content="<?php echo htmlspecialchars($icon, ENT_QUOTES, 'UTF-8'); ?>">

  <link rel="canonical" href="<?php echo $current_url; ?>">

  <link rel="icon" type="image/png" href="<?php echo htmlspecialchars($icon, ENT_QUOTES, 'UTF-8'); ?>">
  <link rel="apple-touch-icon" href="<?php echo htmlspecialchars($icon, ENT_QUOTES, 'UTF-8'); ?>">

  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "WebSite",
    "name": "Open Geode Index",
    "url": "<?php echo current_url_base(); ?>",
    "description": "<?php echo addslashes(SITE_DESCRIPTION); ?>",
    "image": "<?php echo htmlspecialchars($icon, ENT_QUOTES, 'UTF-8'); ?>"
  }
  </script>

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" crossorigin="anonymous">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>

  <style>
    body{overflow-wrap: anywhere;}
    .card-pre{white-space:pre-wrap;}
  </style>
</head>
<body style="padding-top: 80px; min-height: 100vh; display: flex;    flex-direction: column;">
    <nav class="navbar fixed-top navbar-expand-lg border-bottom px-4 bg-black">
        <a class="navbar-brand" href="/ui">Open Geode Index</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#mainNavbar" aria-controls="mainNavbar" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="mainNavbar" style="justify-content: space-between;">
            <ul class="navbar-nav mr-auto">
            <li class="nav-item"><a class="nav-link" href="/developers">Users</a></li>
            <?php if ($is_admin): ?><li class="nav-item"><a class="nav-link" href="/ui/admin">Admin</a></li><?php endif; ?>
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
    <div class="container py-3 border border-bottom-0 rounded-top mt-auto" style="backdrop-filter: brightness(0.7);">
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
    $mods = db_read('mods.json') ?: [];
    $stats = api_stats_payload();
    $user = current_user();
    ui_header('Open Geode Index');
    ?>

<div class="row">

    <div class="col-md-4 my-1 py-1 border-end d-flex flex-column border-2">
        <h3>About project</h3>
        <hr class="my-1 mb-3">
        <p>Welcome to the ALTERNATIVE catalog of mods for Geode, here you can find forbidden or lost mods that are kindly hidden from you. <br><i>Enjoy the underground~</i></p>
        <dl class="row px-2 mb-1">
            <dt class="col-10 border-start my-1">Total mod count</dt><dd class="col-2 text-end border-end btn btn-link rounded-0 btn-sm fs-5 py-0"><?=htmlspecialchars($stats['total_mod_count'] ?? 0)?></dd>
            <dt class="col-10 border-start my-1">Total mod downloads</dt><dd class="col-2 text-end border-end btn btn-link rounded-0 btn-sm fs-5 py-0"><?=htmlspecialchars($stats['total_mod_downloads'] ?? 0)?></dd>
            <dt class="col-10 border-start my-1">Total registered users (devs)</dt><dd class="col-2 text-end border-end btn btn-link rounded-0 btn-sm fs-5 py-0"><?=htmlspecialchars($stats['total_registered_developers'] ?? 0)?></dd>
        </dl>
        <p><a class="btn btn-primary w-100 py-1" href="https://github.com/lil2kki/Open-Geode-Index#how-to-install" target="_blank">Download proxy mod for Geode Loader!</a></p>
        <h3>Submit a mod</h3>
        <hr class="my-1 mb-3">
        <?php if (!$user): ?>
            <div class="alert alert-warning">Please <a href="/login">sign in with GitHub</a> to submit mods.</div>
        <?php else: ?>
            <p class="text-muted">You can post anything you want but malware, pls provide us valid GitHub Repository cuz logo loading form it (user/repo/HEAD/logo.png)<br><br>You also can upload not your mods, but it would be sweet if you go to mod page and change developer displayname on real one instead you.<br><br>If you are developer and ownership of your repository was taken pls <a target="_blank" href="https://github.com/lil2kki/Open-Geode-Index/issues/new">send report here</a> so i give you access.</p>
            <form method="post" action="/v1/mods" class="h-100">
            <div class="form-group">
                <label for="repo">Repository (user/repo)</label>
                <input id="repo" name="repo" class="form-control" placeholder="lil2kki/mod" required>
            </div>
            <div class="form-group my-2">
                <label for="download_link">Download link (.geode)</label>
                <input id="download_link" name="download_link" class="form-control" placeholder="https://github.com/.../releases/download/vX.Y/file.geode" required>
            </div>
            <button class="w-100 btn btn-primary">Submit</button>
            </form><?=asAPIReqForm()?>
        <?php endif; ?>
    </div>
  
  <div class="col-md-8 mt-1 pt-1">
    
    <div class="input-group mb-3">
        <input type="text" id="searchInput" class="form-control" placeholder="Search..." onkeydown="if(event.key==='Enter') findAndScroll(this.value)">
        <button class="btn btn-primary" onclick="findAndScroll(document.getElementById('searchInput').value)">Find</button>
    </div>

    <style> .highlight-search { background: yellow !important; color: black !important; } </style>
    <script>
    function findAndScroll(text) {
        document.querySelectorAll('.highlight-search').forEach(el => { el.classList.remove('highlight-search'); });
        if (text.length < 1) return;
        window.find(text);
        const walker = document.createTreeWalker(
            document.body, NodeFilter.SHOW_TEXT,
            { acceptNode: node => node.textContent.toLowerCase().includes(text.toLowerCase()) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT }
        );
        const nodes = [];
        let node;
        while (node = walker.nextNode()) nodes.push(node);
        if (nodes.length > 0) {
            nodes.forEach(n => {
                const parent = n.parentElement;
                if (!parent.classList.contains('highlight-search')) parent.classList.add('highlight-search');
            });
            const first = nodes[0].parentElement;
            first.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }
    </script>

    <div class="row" style="
        justify-content: space-around;
        align-items: center;
        flex-flow: wrap-reverse;
        align-items: stretch;
        display: flex;
    ">
      <?php if (empty($mods)): ?>
        <div class="col-12"><div class="alert alert-info">No mods available.</div></div>
      <?php else: foreach ($mods as $m): ?>
        <div class="col-sm-6 col-lg-4 p-2" style="text-align: center;">
          <a class="btn btn-outline-secondary card h-100 pt-3" href="/ui/mod/<?=urlencode($m['id'])?>">
            <?php if (!empty($m['logo_url'])): ?><img class="card-img-top" src="<?=htmlspecialchars($m['logo_url'])?>" alt="logo" style="object-fit:scale-down;height:140px;" onerror="this.style.display='none'"><?php endif; ?>
            <div class="card-body d-flex flex-column">
              <h5 class="card-title mb-1"><?=htmlspecialchars($m['id'])?></h5>
              <p class="card-text text-muted"><?=strip_tags(md(strip_tags(mb_strimwidth($m['about'] ?? '', 0, 140, '...')), true), '<p><i><b><strong><code><pre>')?></p>
            </div>
          </a>
        </div>
      <?php endforeach; endif; ?>
    </div>
  </div>
  
</div>
<?php
    ui_footer();
}


function render_devs() {
    $developers = db_read('developers.json') ?: [];
    $user = current_user();
    ui_header('Users - Open Geode Index');
    ?>
    <div class="row px-3" style="
        /* flex-flow: wrap-reverse; */
        justify-content: space-around;
        align-items: center;
        align-items: stretch;
        display: flex;
    ">
      <?php if (empty($developers)): ?>
        <div class="col-12"><div class="alert alert-danger">But nobody came.</div></div>
      <?php else: foreach ($developers as $dev): ?>
        <div style="text-align: center; <?php if ($dev['username'] === $user): ?> order: -1; <?php endif; ?>" class="col-sm-4 col-lg-2 p-2">
          <div class="card h-100 pt-3 <?php if ($dev['username'] === $user): ?> bg-gradient <?php endif; ?>">
            <img class="card-img-top" src="https://github.com/<?=htmlspecialchars($dev['username'])?>.png" alt="logo" style="object-fit:scale-down;height:140px;" onerror="this.style.display='none'">
            <div class="card-body d-flex flex-column">
              <h5 class="card-title mb-1">
                <a target="_blank" href="https://github.com/<?=htmlspecialchars($dev['username'])?>" class="link-body-emphasis link-offset-2 link-underline-opacity-25 link-underline-opacity-75-hover">
                    <?=htmlspecialchars($dev['display_name'])?>
                </a>
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

function render_mod_page($id) {
    $mods = db_read('mods.json') ?: [];
    $mod = null;
    foreach ($mods as $m) if ($m['id'] === $id) { $mod = $m; break; }
    $user = current_user(); 
    $is_admin = is_admin();

    ui_header($id . ' - Open Geode Index');

    if (!$mod) { http_response_code(404); echo "<script>window.location.replace('https://geode-sdk.org/mods/".$id."');</script>"; exit; }

    if ((empty($mod['about']) or !empty($mod['prefer_github_info'])) && !empty($mod['repo'])) {
        $text = fetch_github_raw_text($mod['repo'], 'README.md');
        if ($text === null) $text = fetch_github_raw_text($mod['repo'], 'about.md');
        if ($text !== null) $mod['about'] = $text;
    }
    ?>
<div class="row">
  <div class="col-md-8">
	<div class="" style="display: flex;">
		<?php if (!empty($mod['logo_url'])): ?><img src="<?=htmlspecialchars($mod['logo_url'])?>" alt="logo" style="max-height:80px;" onerror="this.style.display='none'"><?php endif; ?>
		<div class="ms-2">
			<h2><?=htmlspecialchars($mod['id'])?></h2>
			<?php if (!empty($mod['repository'])): ?><p>Repository: <a href="<?=htmlspecialchars($mod['repository'])?>" target="_blank"><?=htmlspecialchars($mod['repository'])?></a></p><?php endif; ?>
		</div>
	</div>

    <ul class="nav nav-underline mx-3">
        <li class="nav-item"><a class="nav-link active" data-toggle="tab" href="#about">About</a></li>
        <li class="nav-item"><a class="nav-link 
        <?php if (empty($mod['changelog'])): ?> disabled <?php endif; ?>
        " data-toggle="tab" href="#changelog">Changelog</a></li>

    </ul>

    <div class="tab-content mt-3">
    <div class="tab-pane active" id="about">
        <p class="mb-0"><?=md(strip_tags($mod['about'] ?? ''))?></p>
    </div>
<?php if (!empty($mod['changelog'])): ?>
    <div class="tab-pane" id="changelog">
        <p class=" mb-0"><?=md(strip_tags($mod['changelog']))?></p>
    </div>
<?php endif; ?>
    </div>

  </div>

  <div class="col-md-4">
  
	<hr>

    <h4>Versions</h4>
    <ul class="list-group mb-3">
      <?php foreach ($mod['versions'] as $v): ?>
        <li class="list-group-item d-flex justify-content-between align-items-center">
          <div><strong><?=htmlspecialchars($v['version'])?></strong></div>
          <div><a class="btn btn-sm btn-success" href="/v1/mods/<?=urlencode($mod['id'])?>/versions/<?=urlencode($v['version'])?>/download">Download</a></div>
        </li>
      <?php endforeach; ?>
    </ul>

    <h5>Developers</h5>
    <div>
      <?php foreach ($mod['developers'] as $d): ?>
        <div class="card <?php if ($d['username'] === $user): ?>bg-gradient<?php endif; ?>">
            <div style="display: flex;">
                <img id="ic-<?=htmlspecialchars($d['username'])?>" src="https://github.com/<?=htmlspecialchars($d['username'])?>.png" class="rounded-start" style="height: 70px;" alt="<?=htmlspecialchars($d['username'])?>">
                <img id="ic-<?=htmlspecialchars($d['display_name'])?>" class="rounded-start" style="height: 70px; display: none;" 
                    src="https://github.com/<?=htmlspecialchars($d['display_name'])?>.png" 
                    alt="<?=htmlspecialchars($d['display_name'])?>" 
                    onload="
                        this.style.display='block'; 
                        document.getElementById('ic-<?=htmlspecialchars($d['username'])?>').style.display='none';
                        document.getElementById('a-<?=htmlspecialchars($d['display_name'])?>').href='https://github.com/<?=htmlspecialchars($d['display_name'])?>';
                    "
                >
                <div class="border-start border-2">
                    <div class="card-body p-1 px-2 pt-2">
                        <h5 class="card-title">
                            <a id="a-<?=htmlspecialchars($d['display_name'])?>" target="_blank" href="https://github.com/<?=htmlspecialchars($d['username'])?>" class="link-body-emphasis link-offset-2 link-underline-opacity-25 link-underline-opacity-75-hover">
                                <?=htmlspecialchars($d['display_name'])?>
                            </a>
                        </h5>
                        <p class="card-text text-body-secondary">
                            <?=htmlspecialchars($d['username'])?> 
                            <?=!empty($d['is_owner']) ? '<a href="https://github.com/'.htmlspecialchars($d['username']).'" class="link-info link-underline-opacity-50">[puplisher]</a>' : ''?>
                        </p>
                    </div>
                </div>
            </div>
        </div>
      <?php endforeach; ?>
    </div>
	
	<hr>
	
    <?php
    $owner_allowed = is_admin();
    if (!$owner_allowed && $user) {
        foreach ($mod['developers'] as $dev) if (!empty($dev['username']) && $dev['username'] === $user && !empty($dev['is_owner'])) { $owner_allowed = true; break; }
    }
    $owner_display = '';
    foreach ($mod['developers'] as $d) {
        if (!empty($d['is_owner'])) { $owner_display = $d['display_name'] ?? ($d['username'] ?? ''); break; }
    }
    if ($owner_allowed): ?>
        <div class="card mb-3">
            <div class="card-body">
            <form method="post" action="/v1/mods/<?=urlencode($mod['id'])?>">
                <h6>Update</h6>

                <div class="form-group my-2">
                    <label for="prefer_github_info">Text source preference:</label>
                    <select id="prefer_github_info" name="prefer_github_info" class="form-control">
                        <option value="0" <?=empty($mod['prefer_github_info']) ? 'selected' : ''?>>From .geode file</option>
                        <option value="1" <?=!empty($mod['prefer_github_info']) ? 'selected' : ''?>>From GitHub Repository</option>
                    </select>
                </div>

                <div class="form-group my-2">
                    <label for="owner_display_name">Owner display name</label>
                    <input id="owner_display_name" name="owner_display_name" class="form-control" value="<?=htmlspecialchars($owner_display)?>">
                </div>

                <div class="form-group my-2">
                    <label for="download_link">Download link</label>
                    <input id="download_link" name="download_link" class="form-control">
                </div>

                <button class="w-100 btn btn-primary btn-block">Submit</button>
            </form><?=asAPIReqForm()?>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($owner_allowed): ?>
      <div class="card mb-3">
        <div class="card-body">
          <form method="post" action="/v1/mods/<?=urlencode($mod['id'])?>" 
      onsubmit="event.preventDefault();if(!confirm('Delete <?=htmlspecialchars($mod['id'])?>?\nAction can\'t be undone...')) return;fetch(this.action, {method:'POST', body:new FormData(this)}).then(() => {history.back(); setTimeout(()=>location.reload(), 200)});">
            <input type="hidden" name="_method" value="DELETE">
            <button type="submit" class="w-100 btn btn-sm btn-danger">Delete mod</button>
          </form>
        </div>
      </div>
    <?php endif; ?>

    <?php if (is_admin()): ?>
      <div class="card">
        <div class="card-body">
          <form method="post" action="/ui/admin">
            <input type="hidden" name="action" value="toggle_featured">
            <input type="hidden" name="modid" value="<?=htmlspecialchars($mod['id'])?>">
            <select name="featured" class="form-control my-1">
                <option value="0" <?=empty($mod['featured']) ? 'selected' : ''?>>Featured: No</option>
                <option value="1" <?=!empty($mod['featured']) ? 'selected' : ''?>>Featured: Yes</option>
            </select>
            <button class="w-100 btn btn-danger btn-block">Apply</button>
          </form>
        </div>
      </div>
    <?php endif; ?>

  </div>
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
            <td><a target="_blank" href="https://github.com/<?=htmlspecialchars($d['username'])?>" target="_blank"><?=htmlspecialchars($d['username'])?></a></td>
            <td><?=htmlspecialchars($d['display_name'])?></td>
            <td><?=!empty($d['verified']) ? 'yes' : 'no'?></td>
            <td><?=!empty($d['admin']) ? 'yes' : 'no'?></td>
            <td>
              <form method="post" action="/ui/admin" style="display:inline-block">
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
        <input type="hidden" name="action" value="create_tag">
        <input name="tag_name" class="form-control mr-2" placeholder="tag name">
        <button class="btn btn-primary">Add tag</button>
      </form>
      <ul><?php foreach ($tags as $t) echo '<li>'.htmlspecialchars(is_array($t)&&isset($t['name'])?$t['name']:(string)$t).'</li>'; ?></ul>

    <?php elseif ($tab === 'deprecations'): ?>
      <h5>Deprecations</h5>
      <form method="post" action="/ui/admin" class="mb-3"><input type="hidden" name="action" value="create_deprecation">
        <div class="form-row">
          <div class="form-group col-md-3"><label>Mod ID</label><input name="modid" class="form-control"></div>
          <div class="form-group col-md-4"><label>By (comma)</label><input name="by" class="form-control"></div>
          <div class="form-group col-md-5"><label>Reason</label><input name="reason" class="form-control"></div>
        </div>
        <button class="btn btn-primary">Create</button>
      </form>
      <table class="table table-sm"><thead><tr><th>Mod</th><th>By</th><th>Reason</th><th>Actions</th></tr></thead><tbody>
        <?php foreach ($deprec as $d): ?>
          <tr><td><?=htmlspecialchars($d['mod_id'])?></td><td><?=htmlspecialchars(implode(', ', $d['by']))?></td><td><?=htmlspecialchars($d['reason'])?></td>
            <td><form method="post" action="/ui/admin"><input type="hidden" name="action" value="delete_deprecation"><input type="hidden" name="modid" value="<?=htmlspecialchars($d['mod_id'])?>"><input type="hidden" name="depid" value="<?=htmlspecialchars($d['id'])?>"><button class="btn btn-sm btn-danger">Delete</button></form></td></tr>
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
      <?php
        $tokens = db_read('tokens.json') ?: [];
        $current = current_user();
      ?>
      <table class="table table-sm"><thead><tr><th>Access token</th><th>Expires at</th><th>Refresh token</th><th>Refresh expires</th><th>Action</th></tr></thead><tbody>
        <?php foreach ($tokens as $k => $meta) {
          if (!empty($meta['username']) && $meta['username'] === $current) {
            echo '<tr><td>'.htmlspecialchars($k).'</td><td>'.htmlspecialchars($meta['expires_at'] ?? '').'</td><td>'.htmlspecialchars($meta['refresh_token'] ?? '').'</td><td>'.htmlspecialchars($meta['refresh_expires_at'] ?? '').'</td><td><form method="post" action="/ui/admin"><input type="hidden" name="action" value="revoke_token"><input type="hidden" name="token" value="'.htmlspecialchars($k).'"><button class="btn btn-sm btn-danger">Revoke</button></form></td></tr>';
          }
        } ?>
      </tbody></table>
    <?php endif; ?>

  </div>
</div>
<?php
    ui_footer();
}

/* helper for admin stats */
function api_stats_payload() {
    $mods = db_read('mods.json') ?: [];
    $devs = db_read('developers.json') ?: [];
    $total_mod_count = count($mods);
    $total_mod_downloads = 0;
    $total_geode_downloads = 0;
    foreach ($mods as $m) $total_mod_downloads += ($m['download_count'] ?? 0);
    return ['total_geode_downloads' => $total_geode_downloads, 'total_mod_count' => $total_mod_count, 'total_mod_downloads' => $total_mod_downloads, 'total_registered_developers' => count($devs)];
}

/* ======================= Admin UI form handler ======================= */
function handle_admin_form() {
    if (!is_admin()) { http_response_code(403); echo "<h1>Forbidden</h1><p>Admin only</p>"; exit; }
    $action = $_POST['action'] ?? '';
    if ($action === 'toggle_featured') {
        $modid = $_POST['modid'] ?? null; $featured = !empty($_POST['featured']) ? true : false;
        $mods = db_read('mods.json') ?: [];
        foreach ($mods as $i => $m) {
            if ($m['id'] === $modid) { $mods[$i]['featured'] = $featured; $mods[$i]['updated_at'] = iso8601_utc(); db_write('mods.json', $mods); $_SESSION['flash'] = 'Mod updated'; header('Location: /ui/admin?tab=mods'); exit; }
        }
        $_SESSION['flash'] = 'Mod not found'; header('Location: /ui/admin?tab=mods'); exit;
    }
    if ($action === 'create_loader_version') {
        $tag = $_POST['tag'] ?? null; $commit_hash = $_POST['commit_hash'] ?? null; $gd = $_POST['gd'] ?? null;
        if (!$tag || !$commit_hash || !$gd) { $_SESSION['flash'] = 'Missing fields'; header('Location:/ui/admin?tab=loader'); exit; }
        $gd_parsed = json_decode($gd, true);
        if ($gd_parsed === null) {
            $parts = array_map('trim', explode(',', $gd));
            $gd_parsed = [];
            foreach ($parts as $p) {
                if (strpos($p, ':') !== false) { list($k, $v) = array_map('trim', explode(':', $p, 2)); if ($k && $v) $gd_parsed[$k] = $v; }
            }
        }
        $body = ['tag' => $tag, 'commit_hash' => $commit_hash, 'gd' => $gd_parsed];
        // call API create
        $_POST = $body;
        return api_loader_versions_create();
    }
    if ($action === 'update_developer') {
        $id = intval($_POST['developer_id'] ?? 0); $admin = isset($_POST['admin']) ? (bool)$_POST['admin'] : null; $verified = isset($_POST['verified']) ? (bool)$_POST['verified'] : null;
        $body = [];
        if ($admin !== null) $body['admin'] = $admin;
        if ($verified !== null) $body['verified'] = $verified;
        $_POST = $body;
        return api_developers_update($id);
    }
    if ($action === 'create_tag') {
        $name = trim($_POST['tag_name'] ?? '');
        if ($name === '') { $_SESSION['flash'] = 'Tag name required'; header('Location:/ui/admin?tab=tags'); exit; }
        $tags = db_read('tags.json') ?: [];
        $tags[] = ['id' => time(), 'name' => $name, 'display_name' => $name, 'is_readonly' => false];
        db_write('tags.json', $tags);
        $_SESSION['flash'] = 'Tag created'; header('Location:/ui/admin?tab=tags'); exit;
    }
    if ($action === 'create_deprecation') {
        $modid = $_POST['modid'] ?? ''; $by = isset($_POST['by']) ? array_map('trim', explode(',', $_POST['by'])) : []; $reason = $_POST['reason'] ?? '';
        $_POST = ['by' => $by, 'reason' => $reason];
        return api_deprecations_create($modid);
    }
    if ($action === 'delete_deprecation') {
        $modid = $_POST['modid'] ?? ''; $depid = intval($_POST['depid'] ?? 0);
        return api_deprecations_delete($modid, $depid);
    }
    if ($action === 'revoke_token') {
        $token = $_POST['token'] ?? '';
        $tokens = db_read('tokens.json') ?: [];
        if (isset($tokens[$token])) { unset($tokens[$token]); db_write('tokens.json', $tokens); $_SESSION['flash'] = 'Token revoked'; } else $_SESSION['flash'] = 'Token not found';
        header('Location: /ui/admin?tab=tokens'); exit;
    }
    $_SESSION['flash'] = 'Unknown admin action';
    header('Location: /ui/admin'); exit;
}

/* ======================= WEB auth handlers (UI flows) ======================= */
function handle_login() {
    if (!defined('CLIENT_ID') || CLIENT_ID === '') {
        echo "<h1>GitHub OAuth not configured</h1><p>Please set CLIENT_ID and CLIENT_SECRET in index.php</p>";
        exit;
    }
    $state = bin2hex(random_bytes(12));
    $_SESSION['oauth_state'] = $state;
    $params = http_build_query([
        'client_id' => CLIENT_ID,
        'redirect_uri' => CALLBACK_URL ?: current_url_base() . '/callback',
        'scope' => 'read:user',
        'state' => $state,
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
    $code = $_GET['code']; $state = $_GET['state'];
    if (!isset($_SESSION['oauth_state']) || $_SESSION['oauth_state'] !== $state) { echo "Invalid state"; exit; }
    $token = github_exchange_code($code);
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
?>
