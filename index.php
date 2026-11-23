<?php
// Start buffering before config so BOM/whitespace/debug output cannot corrupt API JSON.
ob_start();
require_once __DIR__ . '/_config.php';
if (ob_get_level() > 0) @ob_clean();

define('DATA_DIR', __DIR__ . '/data');
define('SESSION_COOKIE', 'ogi_session');
define('ACCESS_TOKEN_TTL', 60 * 60 * 24 * 7);
define('REFRESH_TOKEN_TTL', 60 * 60 * 24 * 30);
define('DEBUG', false);
define('MAX_UPLOAD_BYTES', 120 * 1024 * 1024);
define('UPSTREAM_CACHE_TTL', 300);

@ini_set('display_errors', '0');
@ini_set('display_startup_errors', '0');
@ini_set('log_errors', '1');
error_reporting(E_ALL);

register_shutdown_function(function () {
    $error = error_get_last();
    if (!$error || !in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) return;
    error_log('[OGI] Fatal PHP error: ' . ($error['message'] ?? 'unknown') . ' in ' . ($error['file'] ?? 'unknown') . ':' . ($error['line'] ?? 0));
    $path = parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';
    if (strpos($path, '/v1/') !== 0 || headers_sent()) return;
    while (ob_get_level() > 0) @ob_end_clean();
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    echo '{"error":"Internal server error","payload":null}';
});

if (!is_dir(DATA_DIR)) @mkdir(DATA_DIR, 0700, true);
if (is_dir(DATA_DIR)) {
    @chmod(DATA_DIR, 0700);
    // tokens.json and access.log live under the web root on common shared hosts.
    // Deny direct HTTP access on Apache and restrict filesystem permissions elsewhere.
    $deny_rules = DATA_DIR . '/.htaccess';
    if (!is_file($deny_rules)) {
        @file_put_contents($deny_rules, "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule mod_access_compat.c>\nDeny from all\n</IfModule>\n", LOCK_EX);
        @chmod($deny_rules, 0600);
    }
    foreach (glob(DATA_DIR . '/*.json') ?: [] as $data_file) @chmod($data_file, 0600);
    if (is_file(DATA_DIR . '/access.log')) @chmod(DATA_DIR . '/access.log', 0600);
}

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name(SESSION_COOKIE);
    $is_https = !empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off';
    @session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $is_https,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

/* ======================= [PATCH] SECURITY & INFRA ======================= */

// CSRF token per session
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
define('CSRF_TOKEN', $_SESSION['csrf']);

function csrf_check_if_session() {
    // Bearer authentication is not vulnerable to browser CSRF.
    if (empty($_SESSION['github_user'])) return;

    $headers = getallheaders_lower();
    $sent = $headers['x-csrf-token'] ?? ($_POST['csrf'] ?? '');
    if ($sent === '' && in_array($_SERVER['REQUEST_METHOD'] ?? '', ['PUT', 'PATCH', 'DELETE'], true)) {
        $body = json_input();
        if (is_array($body)) $sent = $body['csrf'] ?? '';
    }

    if (!is_string($sent) || $sent === '' || !hash_equals(CSRF_TOKEN, $sent)) {
        if (function_exists('is_browser_form_request') && is_browser_form_request()) {
            publish_form_response(['error' => 'CSRF token mismatch. Reload the page and submit again.', 'payload' => null], 403);
        }
        json_response(['error' => 'CSRF token mismatch', 'payload' => null], 403);
    }
}

// Simple file-based rate limiter keyed by IP. $bucket is its own namespace.
function rate_limit($bucket, $max = 300, $window = 60) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $key = $bucket . ':' . $ip;
    $data = db_read('ratelimit.json');
    if (!is_array($data)) $data = [];
    $now = time();

    // Periodic cleanup
    if (mt_rand(1, 50) === 1) {
        foreach ($data as $k => $v) if (!is_array($v) || (int)($v['reset'] ?? 0) < $now) unset($data[$k]);
    }

    $b = isset($data[$key]) && is_array($data[$key]) ? $data[$key] : ['count' => 0, 'reset' => $now + $window];
    if ($now > (int)($b['reset'] ?? 0)) $b = ['count' => 0, 'reset' => $now + $window];
    $b['count'] = max(0, (int)($b['count'] ?? 0)) + 1;
    $data[$key] = $b;
    db_write('ratelimit.json', $data);

    if ($b['count'] > $max) {
        header('Retry-After: ' . max(1, $b['reset'] - $now));
        json_response(['error' => 'rate limit exceeded', 'payload' => null], 429);
    }
}

function api_log($action, $data = []) {
    $line = json_encode_safe([
        'ts'     => gmdate('Y-m-d\TH:i:s\Z'),
        'ip'     => $_SERVER['REMOTE_ADDR'] ?? null,
        'method' => $_SERVER['REQUEST_METHOD'] ?? null,
        'uri'    => $_SERVER['REQUEST_URI'] ?? null,
        'user'   => current_user(),
        'action' => $action,
        'data'   => $data,
    ], false);
    @file_put_contents(DATA_DIR . '/access.log', $line . "\n", FILE_APPEND | LOCK_EX);
}

// [PATCH] SSRF protection. Allow only http/https and public IPs.
function is_safe_url($url) {
    if (!is_string($url) || $url === '' || strlen($url) > 4096) return false;
    if (preg_match('/[\x00-\x20\x7f\\\\]/', $url)) return false;

    $parts = @parse_url($url);
    if (!is_array($parts)) return false;
    $scheme = strtolower($parts['scheme'] ?? '');
    if (!in_array($scheme, ['http', 'https'], true)) return false;
    if (!empty($parts['user']) || !empty($parts['pass'])) return false;

    $host = strtolower(rtrim((string)($parts['host'] ?? ''), '.'));
    if ($host === '' || $host === 'localhost' || strpos($host, '.') === false && !filter_var($host, FILTER_VALIDATE_IP)) return false;
    if (isset($parts['port']) && ((int)$parts['port'] < 1 || (int)$parts['port'] > 65535)) return false;

    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ips[] = $host;
    } elseif (function_exists('dns_get_record')) {
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $record) {
                if (!empty($record['ip'])) $ips[] = $record['ip'];
                if (!empty($record['ipv6'])) $ips[] = $record['ipv6'];
            }
        }
    }
    if (!$ips) {
        $resolved = @gethostbyname($host);
        if ($resolved && $resolved !== $host) $ips[] = $resolved;
    }
    if (!$ips) return false;

    foreach (array_unique($ips) as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return false;
    }
    return true;
}

function response_status_from_headers($headers) {
    $status = null;
    foreach ((array)$headers as $line) {
        if (preg_match('/^HTTP\/[0-9.]+\s+([0-9]{3})/i', (string)$line, $m)) $status = (int)$m[1];
    }
    return $status;
}

function response_header_value($headers, $name) {
    $value = null;
    foreach ((array)$headers as $line) {
        if (stripos((string)$line, $name . ':') === 0) $value = trim(substr((string)$line, strlen($name) + 1));
    }
    return $value;
}

function resolve_relative_url($base_url, $location) {
    $location = trim((string)$location);
    if ($location === '' || preg_match('/[\r\n\x00]/', $location)) return null;
    $loc = @parse_url($location);
    if (!is_array($loc)) return null;
    if (!empty($loc['scheme'])) return $location;

    $base = @parse_url($base_url);
    if (!is_array($base) || empty($base['scheme']) || empty($base['host'])) return null;
    $scheme = $base['scheme'];
    $authority = $scheme . '://' . $base['host'] . (isset($base['port']) ? ':' . $base['port'] : '');

    if (strpos($location, '//') === 0) return $scheme . ':' . $location;
    if (isset($loc['path']) && $loc['path'] !== '') {
        $path = $loc['path'];
        if (substr($path, 0, 1) !== '/') {
            $base_path = $base['path'] ?? '/';
            $path = rtrim(substr($base_path, 0, strrpos($base_path, '/') !== false ? strrpos($base_path, '/') + 1 : 0), '/') . '/' . $path;
        }
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') continue;
            if ($segment === '..') { array_pop($segments); continue; }
            $segments[] = $segment;
        }
        $path = '/' . implode('/', $segments);
    } else {
        $path = $base['path'] ?? '/';
    }

    $query = array_key_exists('query', $loc) ? '?' . $loc['query'] : ((!isset($loc['path']) || $loc['path'] === '') && isset($base['query']) ? '?' . $base['query'] : '');
    return $authority . $path . $query;
}

function open_remote_stream($url, $timeout = 20, $max_redirects = 8) {
    $current = trim((string)$url);
    for ($redirect = 0; $redirect <= $max_redirects; $redirect++) {
        if (!is_safe_url($current)) {
            $GLOBALS['OGI_REMOTE_FETCH_ERROR'] = 'The download URL or one of its redirects failed the public URL safety check.';
            return null;
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => "User-Agent: Open-Geode-Index/2.0\r\nAccept: */*\r\nConnection: close\r\n",
                'timeout' => max(1, (int)$timeout),
                'ignore_errors' => true,
                'follow_location' => 0,
                'max_redirects' => 0,
                'protocol_version' => 1.1,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);

        unset($http_response_header);
        $stream = @fopen($current, 'rb', false, $context);
        if ($stream === false) {
            $last = error_get_last();
            $detail = is_array($last) && !empty($last['message']) ? ': ' . clean_utf8((string)$last['message']) : '';
            $GLOBALS['OGI_REMOTE_FETCH_ERROR'] = 'Could not connect to the download URL (DNS, TLS, network or host restriction)' . $detail;
            return null;
        }
        $headers = isset($http_response_header) ? $http_response_header : [];
        $status = response_status_from_headers($headers);

        if ($status !== null && in_array($status, [301, 302, 303, 307, 308], true)) {
            $location = response_header_value($headers, 'Location');
            fclose($stream);
            if ($location === null || $redirect >= $max_redirects) {
                $GLOBALS['OGI_REMOTE_FETCH_ERROR'] = 'The download redirect is missing or exceeded the redirect limit.';
                return null;
            }
            $next = resolve_relative_url($current, $location);
            if ($next === null || !is_safe_url($next)) {
                $GLOBALS['OGI_REMOTE_FETCH_ERROR'] = 'The download redirected to an invalid or blocked host.';
                return null;
            }
            $current = $next;
            continue;
        }

        if ($status === null || $status < 200 || $status >= 300) {
            fclose($stream);
            $GLOBALS['OGI_REMOTE_FETCH_ERROR'] = 'The download host returned HTTP ' . ($status === null ? 'without a valid status' : $status) . '.';
            return null;
        }
        return ['stream' => $stream, 'url' => $current, 'status' => $status, 'headers' => $headers];
    }
    return null;
}

/* ======================= BOOT ======================= */

$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$uri = parse_url((string)($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';
if ($uri !== '/' && substr($uri, -1) === '/') $uri = rtrim($uri, '/');

// [PATCH] Global rate limit. GET/HEAD generous, everything else stricter.
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
    if (preg_match('#^/ui/mod/([^/]+)$#', $uri, $m) && $method === 'GET') return render_mod_page(rawurldecode($m[1]));
    if ($uri === '/ui/admin' && $method === 'GET') return render_admin_page();
    if ($uri === '/ui/admin' && $method === 'POST') return handle_admin_form();

    // [PATCH] extended /health
    if ($uri === '/health' && $method === 'GET') {
        $upstream_ok = false;
        if (defined('UPSTREAM_URL') && is_string(UPSTREAM_URL) && is_safe_url(rtrim(UPSTREAM_URL, '/'))) {
            $remote = open_remote_stream(rtrim(UPSTREAM_URL, '/') . '/health', 5, 2);
            if ($remote !== null) { $upstream_ok = $remote['status'] >= 200 && $remote['status'] < 300; fclose($remote['stream']); }
        }
        return json_response([
            'status'             => 'ok',
            'time'               => gmdate('Y-m-d\TH:i:s\Z'),
            'data_dir_writable'  => is_writable(DATA_DIR),
            'zip_available'      => class_exists('ZipArchive'),
            'allow_url_fopen'    => filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN),
            'openssl_available'  => extension_loaded('openssl'),
            'mbstring_available' => extension_loaded('mbstring'),
            'upstream'           => $upstream_ok ? 'ok' : 'unreachable',
        ]);
    }

    // tags (cacheable)
    if ($uri === '/v1/tags' && $method === 'GET') return api_tags_index();
    if ($uri === '/v1/detailed-tags' && $method === 'GET') return api_tags_detailed();

    // developers
    if ($uri === '/v1/developers' && $method === 'GET') return api_developers_index();
    if (preg_match('#^/v1/developers/(\d+)$#', $uri, $m)) {
        if ($method === 'GET') return api_developers_get((int)$m[1]);
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
        if ($method === 'GET') return api_mods_get(rawurldecode($m[1]));
        if ($method === 'PUT') { csrf_check_if_session(); return api_mods_update_admin(rawurldecode($m[1])); }
        if ($method === 'POST') {
            csrf_check_if_session();
            if (!empty($_POST['_method']) && strtoupper($_POST['_method']) === 'DELETE') return api_mods_delete(rawurldecode($m[1]));
            return api_mods_update_owner(rawurldecode($m[1]));
        }
        if ($method === 'DELETE') { csrf_check_if_session(); return api_mods_delete(rawurldecode($m[1])); }
    }

    if (preg_match('#^/v1/mods/([^/]+)/deprecations$#', $uri, $m)) {
        if ($method === 'GET') return api_deprecations_index(rawurldecode($m[1]));
        if ($method === 'POST') { csrf_check_if_session(); return api_deprecations_create(rawurldecode($m[1])); }
        if ($method === 'DELETE') { csrf_check_if_session(); return api_deprecations_clear_all(rawurldecode($m[1])); }
    }
    if (preg_match('#^/v1/mods/([^/]+)/deprecations/(\d+)$#', $uri, $m)) {
        if ($method === 'PUT') { csrf_check_if_session(); return api_deprecations_update(rawurldecode($m[1]), (int)$m[2]); }
        if ($method === 'DELETE') { csrf_check_if_session(); return api_deprecations_delete(rawurldecode($m[1]), (int)$m[2]); }
    }

    if (preg_match('#^/v1/mods/([^/]+)/developers$#', $uri, $m) && $method === 'POST') { csrf_check_if_session(); return api_mod_add_developer(rawurldecode($m[1])); }
    if (preg_match('#^/v1/mods/([^/]+)/developers/([^/]+)$#', $uri, $m) && $method === 'DELETE') { csrf_check_if_session(); return api_mod_remove_developer(rawurldecode($m[1]), rawurldecode($m[2])); }

    if (preg_match('#^/v1/mods/([^/]+)/logo$#', $uri, $m) && $method === 'GET') return api_mod_logo(rawurldecode($m[1]));

    if (preg_match('#^/v1/mods/([^/]+)/versions$#', $uri, $m)) {
        if ($method === 'GET') return api_mod_versions_index(rawurldecode($m[1]));
        if ($method === 'POST') { csrf_check_if_session(); return api_mod_versions_create(rawurldecode($m[1])); }
    }
    if (preg_match('#^/v1/mods/([^/]+)/versions/([^/]+)$#', $uri, $m)) {
        if ($method === 'GET') return api_mod_versions_get(rawurldecode($m[1]), rawurldecode($m[2]));
        if ($method === 'PUT') { csrf_check_if_session(); return api_mod_versions_update(rawurldecode($m[1]), rawurldecode($m[2])); }
    }
    if (preg_match('#^/v1/mods/([^/]+)/versions/([^/]+)/download$#', $uri, $m) && $method === 'GET') return api_mod_versions_download(rawurldecode($m[1]), rawurldecode($m[2]));

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
    $tmp = fetch_remote_file_to_temp($url, $max_bytes, $timeout, $max_redirects);
    if ($tmp === null) return null;
    $hash = @hash_file('sha256', $tmp);
    @unlink($tmp);
    return $hash === false ? null : $hash;
}

function fetch_remote_file_to_temp($url, $max_bytes = MAX_UPLOAD_BYTES, $timeout = 35, $max_redirects = 8) {
    $remote = open_remote_stream($url, $timeout, $max_redirects);
    if ($remote === null) return null;

    $content_length = response_header_value($remote['headers'], 'Content-Length');
    if ($content_length !== null && ctype_digit($content_length) && (int)$content_length > $max_bytes) {
        fclose($remote['stream']);
        $GLOBALS['OGI_REMOTE_FETCH_ERROR'] = 'The .geode archive is larger than the configured 120 MiB inspection limit.';
        return null;
    }

    $temp_dir = DATA_DIR . '/tmp';
    if (!is_dir($temp_dir) && !@mkdir($temp_dir, 0700, true) && !is_dir($temp_dir)) {
        fclose($remote['stream']);
        $GLOBALS['OGI_REMOTE_FETCH_ERROR'] = 'Cannot create the private data/tmp directory. Check DATA_DIR permissions.';
        error_log('[OGI] ' . $GLOBALS['OGI_REMOTE_FETCH_ERROR']);
        return null;
    }
    @chmod($temp_dir, 0700);
    if (!is_writable($temp_dir)) {
        fclose($remote['stream']);
        $GLOBALS['OGI_REMOTE_FETCH_ERROR'] = 'The private data/tmp directory is not writable.';
        error_log('[OGI] ' . $GLOBALS['OGI_REMOTE_FETCH_ERROR']);
        return null;
    }
    $tmp = @tempnam($temp_dir, 'ogi_');
    if ($tmp === false || realpath(dirname($tmp)) !== realpath($temp_dir)) {
        if (is_string($tmp) && $tmp !== '') @unlink($tmp);
        fclose($remote['stream']);
        $GLOBALS['OGI_REMOTE_FETCH_ERROR'] = 'Cannot create a temporary file in the private data/tmp directory.';
        error_log('[OGI] ' . $GLOBALS['OGI_REMOTE_FETCH_ERROR']);
        return null;
    }
    @chmod($tmp, 0600);
    $out = @fopen($tmp, 'wb');
    if ($out === false) {
        fclose($remote['stream']);
        @unlink($tmp);
        $GLOBALS['OGI_REMOTE_FETCH_ERROR'] = 'Cannot open the temporary archive for writing.';
        return null;
    }

    $read = 0;
    $failed = false;
    while (!feof($remote['stream'])) {
        $remaining = ($max_bytes + 1) - $read;
        if ($remaining <= 0) break;
        $chunk = @fread($remote['stream'], min(8192, $remaining));
        if ($chunk === false) { $failed = true; break; }
        if ($chunk === '') {
            if (!feof($remote['stream'])) $failed = true;
            break;
        }
        $length = strlen($chunk);
        $read += $length;
        if ($read > $max_bytes) { $failed = true; break; }
        if (fwrite($out, $chunk) !== $length) { $failed = true; break; }
    }

    fclose($remote['stream']);
    fclose($out);
    if ($failed || $read === 0) {
        @unlink($tmp);
        $GLOBALS['OGI_REMOTE_FETCH_ERROR'] = $read === 0 ? 'The download returned an empty file.' : 'The download was interrupted or could not be written to disk.';
        return null;
    }
    return $tmp;
}

function clean_utf8($value) {
    if (!is_string($value) || preg_match('//u', $value)) return $value;
    if (function_exists('iconv')) {
        $converted = @iconv('UTF-8', 'UTF-8//IGNORE', $value);
        if ($converted !== false) return $converted;
    }
    return preg_replace('/[\\x80-\\xFF]/', "�", $value);
}

function extract_metadata_from_geode_file($file) {
    if (!class_exists('ZipArchive')) return null;
    $zip = new ZipArchive();
    $opened = $zip->open($file, defined('ZipArchive::CHECKCONS') ? ZipArchive::CHECKCONS : 0);
    if ($opened !== true) return null;
    if ($zip->numFiles < 1 || $zip->numFiles > 20000) { $zip->close(); return null; }

    $result = ['modjson' => null, 'about' => null, 'changelog' => null, 'modjson_error' => null];
    $found = ['mod.json' => null, 'about' => null, 'readme' => null, 'changelog' => null];

    for ($i = 0; $i < $zip->numFiles; $i++) {
        $name = $zip->getNameIndex($i);
        if (!is_string($name)) continue;
        $base = strtolower(basename(str_replace('\\', '/', $name)));
        if ($base === 'mod.json' && $found['mod.json'] === null) $found['mod.json'] = $i;
        elseif (in_array($base, ['about.md', 'about', 'about.txt'], true) && $found['about'] === null) $found['about'] = $i;
        elseif (in_array($base, ['readme.md', 'readme', 'readme.txt'], true) && $found['readme'] === null) $found['readme'] = $i;
        elseif (in_array($base, ['changelog.md', 'changelog', 'change.log', 'changes.md'], true) && $found['changelog'] === null) $found['changelog'] = $i;
    }

    if ($found['mod.json'] !== null) {
        $stat = $zip->statIndex($found['mod.json']);
        if (is_array($stat) && (int)($stat['size'] ?? 0) <= 1024 * 1024) {
            $raw = $zip->getFromIndex($found['mod.json']);
            if ($raw !== false) {
                $raw = preg_replace('/^\\xEF\\xBB\\xBF/', '', $raw);
                $decoded = json_decode($raw, true, 64, JSON_BIGINT_AS_STRING);
                if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) $result['modjson'] = $decoded;
                else $result['modjson_error'] = json_last_error_msg();
            }
        } else {
            $result['modjson_error'] = 'mod.json exceeds the 1 MiB limit';
        }
    }

    $read_entry = function ($index) use ($zip) {
        if ($index === null) return null;
        $stat = $zip->statIndex($index);
        if (!is_array($stat) || (int)($stat['size'] ?? 0) > 2 * 1024 * 1024) return null;
        $raw = $zip->getFromIndex($index);
        return $raw === false ? null : clean_utf8($raw);
    };

    $result['about'] = $read_entry($found['about']);
    if ($result['about'] === null) $result['about'] = $read_entry($found['readme']);
    $result['changelog'] = $read_entry($found['changelog']);

    $zip->close();
    return $result;
}

function extract_metadata_from_geode($download_url) {
    $tmp = fetch_remote_file_to_temp($download_url);
    if ($tmp === null) return null;
    try {
        return extract_metadata_from_geode_file($tmp);
    } finally {
        @unlink($tmp);
    }
}

function github_release_tag_from_download_url($repo, $download_url) {
    if (!is_string($download_url) || $download_url === '') return null;
    $parts = @parse_url($download_url);
    if (!is_array($parts)) return null;
    $host = strtolower((string)($parts['host'] ?? ''));
    if (!in_array($host, ['github.com', 'www.github.com'], true)) return null;

    $path = (string)($parts['path'] ?? '');
    $repo_pattern = preg_quote($repo, '#');
    if (!preg_match('#^/' . $repo_pattern . '/releases/download/([^/]+)/[^/]+$#i', $path, $match)) return null;
    $tag = rawurldecode($match[1]);
    if ($tag === '' || strlen($tag) > 128 || preg_match('/[\x00-\x20\x7f]/', $tag)) return null;
    return $tag;
}

function fetch_github_repo_metadata($repo, $preferred_ref = null) {
    $repo = normalize_github_repo($repo);
    if ($repo === null) return null;

    $refs = [];
    if (is_string($preferred_ref) && $preferred_ref !== '') $refs[] = $preferred_ref;
    $refs[] = 'HEAD';
    $refs = array_values(array_unique($refs));

    foreach ($refs as $ref) {
        $modjson = fetch_github_raw_json($repo, 'mod.json', $ref);
        if (!is_array($modjson)) continue;

        $about = fetch_github_raw_text($repo, 'about.md', $ref);
        if ($about === null || trim($about) === '') $about = fetch_github_raw_text($repo, 'README.md', $ref);
        if ($about === null || trim($about) === '') $about = fetch_github_raw_text($repo, 'readme.md', $ref);
        $changelog = fetch_github_raw_text($repo, 'changelog.md', $ref);
        if ($changelog === null || trim($changelog) === '') $changelog = fetch_github_raw_text($repo, 'CHANGELOG.md', $ref);

        return [
            'modjson' => $modjson,
            'about' => $about !== false ? $about : null,
            'changelog' => $changelog !== false ? $changelog : null,
            'modjson_error' => null,
            'source' => 'github_repository',
            'repository_ref' => $ref,
        ];
    }
    return null;
}

function fetch_github_release_sha256($repo, $download_url) {
    $repo = normalize_github_repo($repo);
    if ($repo === null || !is_string($download_url) || $download_url === '') return null;

    $api_urls = [];
    $tag = github_release_tag_from_download_url($repo, $download_url);
    if ($tag !== null) $api_urls[] = 'https://api.github.com/repos/' . $repo . '/releases/tags/' . rawurlencode($tag);
    $api_urls[] = 'https://api.github.com/repos/' . $repo . '/releases?per_page=100';

    foreach (array_unique($api_urls) as $api_url) {
        $context = stream_context_create(['http' => [
            'method' => 'GET',
            'header' => "User-Agent: Open-Geode-Index/2.0\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\n",
            'timeout' => 8,
            'ignore_errors' => true,
        ]]);
        $raw = @file_get_contents($api_url, false, $context);
        if (!is_string($raw) || strlen($raw) > 4 * 1024 * 1024) continue;
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) continue;
        $releases = isset($decoded['assets']) ? [$decoded] : $decoded;

        foreach ($releases as $release) {
            foreach (($release['assets'] ?? []) as $asset) {
                if ((string)($asset['browser_download_url'] ?? '') !== $download_url) continue;
                $digest = (string)($asset['digest'] ?? '');
                if (preg_match('/^sha256:([a-f0-9]{64})$/i', $digest, $match)) return strtolower($match[1]);
            }
        }
    }
    return null;
}

function inspect_remote_geode_with_repo_fallback($download_url, $repo) {
    // One download is used for both ZIP metadata extraction and the required SHA-256.
    $inspection = inspect_remote_geode($download_url);
    if (empty($inspection['error'])) {
        $inspection['metadata_source'] = 'geode_archive';
        $inspection['metadata_warning'] = null;
        return $inspection;
    }

    $repo = normalize_github_repo($repo);
    if ($repo !== null) {
        $release_tag = github_release_tag_from_download_url($repo, $download_url);
        $repo_metadata = fetch_github_repo_metadata($repo, $release_tag);
        if (is_array($repo_metadata) && !empty($repo_metadata['modjson']) &&
            !empty($repo_metadata['modjson']['id']) && is_scalar($repo_metadata['modjson']['id'])) {
            $release_hash = fetch_github_release_sha256($repo, $download_url);
            if ($release_hash !== null) {
                return [
                    'metadata' => $repo_metadata,
                    'hash' => $release_hash,
                    'metadata_source' => 'github_repository',
                    'metadata_warning' => 'The archive could not be inspected directly. Metadata and the asset SHA-256 were recovered from GitHub.',
                    'inspection_warning' => $inspection['error'],
                ];
            }

            return [
                'error' => 'The .geode archive could not be inspected: ' . $inspection['error'] . ' The repository metadata was found, but GitHub does not provide a SHA-256 digest for this release asset. The index cannot publish a usable Geode version without the archive checksum. Fix the server data/tmp permissions or provide an accessible .geode file.',
            ];
        }
    }

    $reason = $inspection['error'];
    if ($repo !== null) $reason .= ' Also could not read a valid mod.json from the GitHub release tag or repository root.';
    return ['error' => $reason];
}

function inspect_remote_geode($download_url) {
    if (!class_exists('ZipArchive')) return ['error' => 'PHP ZipArchive extension is not installed'];
    $tmp = fetch_remote_file_to_temp($download_url);
    if ($tmp === null) {
        $reason = $GLOBALS['OGI_REMOTE_FETCH_ERROR'] ?? 'The remote archive could not be downloaded.';
        return ['error' => 'Could not download the .geode file: ' . $reason];
    }

    try {
        $hash = @hash_file('sha256', $tmp);
        if ($hash === false) return ['error' => 'Could not calculate SHA-256 for the .geode file'];
        $metadata = extract_metadata_from_geode_file($tmp);
        if ($metadata === null) return ['error' => 'The download is not a readable .geode ZIP archive'];
        if (empty($metadata['modjson']) || !is_array($metadata['modjson'])) {
            $detail = !empty($metadata['modjson_error']) ? ': ' . $metadata['modjson_error'] : '';
            return ['error' => 'mod.json was not found or is invalid inside the .geode archive' . $detail];
        }
        return ['metadata' => $metadata, 'hash' => $hash];
    } finally {
        @unlink($tmp);
    }
}

function json_encode_safe($data, $pretty = false) {
    $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR;
    if ($pretty) $flags |= JSON_PRETTY_PRINT;
    $json = json_encode($data, $flags);
    if ($json === false) {
        error_log('[OGI] JSON encoding failed: ' . json_last_error_msg());
        return '{"error":"JSON encoding failed","payload":null}';
    }
    return $json;
}

function discard_output_buffers() {
    while (ob_get_level() > 0) @ob_end_clean();
}

function json_response($data, $status = 200) {
    discard_output_buffers();
    http_response_code((int)$status);
    header('X-Content-Type-Options: nosniff');
    if (in_array((int)$status, [204, 304], true)) {
        header('Content-Length: 0');
        exit;
    }
    header('Content-Type: application/json; charset=utf-8');
    $body = json_encode_safe($data, DEBUG);
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

function json_response_etag($data, $status = 200, $ttl = 60) {
    $body = json_encode_safe($data, false);
    $etag = '"' . hash('sha256', $body) . '"';
    header('ETag: ' . $etag);
    header('Cache-Control: public, max-age=' . max(0, (int)$ttl));
    if (trim((string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? '')) === $etag) {
        discard_output_buffers();
        http_response_code(304);
        header('Content-Length: 0');
        exit;
    }
    discard_output_buffers();
    http_response_code((int)$status);
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

function db_read($file) {
    if (!preg_match('/^[a-zA-Z0-9_.-]+$/', (string)$file)) return null;
    $path = DATA_DIR . '/' . $file;
    if (!is_file($path)) return null;
    $handle = @fopen($path, 'rb');
    if ($handle === false) return null;
    @flock($handle, LOCK_SH);
    $contents = stream_get_contents($handle);
    @flock($handle, LOCK_UN);
    fclose($handle);
    if ($contents === false || trim($contents) === '') return null;
    $decoded = json_decode($contents, true, 512, JSON_BIGINT_AS_STRING);
    if (json_last_error() !== JSON_ERROR_NONE) {
        error_log('[OGI] Invalid JSON in data file ' . $file . ': ' . json_last_error_msg());
        return null;
    }
    return $decoded;
}

function db_write($file, $data) {
    if (!preg_match('/^[a-zA-Z0-9_.-]+$/', (string)$file)) return false;
    if (!is_dir(DATA_DIR) && !@mkdir(DATA_DIR, 0755, true) && !is_dir(DATA_DIR)) return false;

    $path = DATA_DIR . '/' . $file;
    $lock = @fopen($path . '.lock', 'c');
    if ($lock === false) return false;
    if (!@flock($lock, LOCK_EX)) { fclose($lock); return false; }

    $json = json_encode_safe($data, true);
    $tmp = @tempnam(DATA_DIR, 'ogi_tmp_');
    $ok = false;
    if ($tmp !== false) {
        $written = @file_put_contents($tmp, $json, LOCK_EX);
        if ($written === strlen($json)) {
            @chmod($tmp, 0600);
            $ok = @rename($tmp, $path);
        }
        if (!$ok) @unlink($tmp);
    }

    @flock($lock, LOCK_UN);
    fclose($lock);
    if (!$ok) error_log('[OGI] Failed to write data file ' . $file);
    return $ok;
}

function json_input() {
    static $parsed = false;
    static $body = null;
    if ($parsed) return $body;
    $parsed = true;
    $GLOBALS['OGI_INPUT_ERROR'] = null;

    // Prefer PHP's parsed fields for multipart/form-data. php://input may be unavailable or
    // contain a multipart boundary depending on PHP configuration.
    if (!empty($_POST)) {
        $body = $_POST;
    } else {
        $raw = file_get_contents('php://input');
        $raw = is_string($raw) ? trim($raw) : '';
        if ($raw === '') {
            if (!empty($_SERVER['CONTENT_LENGTH'])) $GLOBALS['OGI_INPUT_ERROR'] = 'Request body is empty (check post_max_size on the server)';
            return null;
        }

        $content_type = strtolower(trim(explode(';', (string)($_SERVER['CONTENT_TYPE'] ?? ''))[0]));
        $looks_json = in_array($content_type, ['application/json', 'text/json'], true)
            || preg_match('/^\\s*[\\[{]/', $raw);
        if ($looks_json || strpos($content_type, '+json') !== false) {
            $decoded = json_decode($raw, true, 512, JSON_BIGINT_AS_STRING);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $GLOBALS['OGI_INPUT_ERROR'] = 'Invalid JSON: ' . json_last_error_msg();
                return null;
            }
            if (!is_array($decoded)) {
                $GLOBALS['OGI_INPUT_ERROR'] = 'JSON body must be an object or array';
                return null;
            }
            $body = $decoded;
        } elseif ($content_type === 'application/x-www-form-urlencoded' || strpos($raw, '=') !== false) {
            parse_str($raw, $body);
        } else {
            $GLOBALS['OGI_INPUT_ERROR'] = 'Unsupported request content type';
            return null;
        }
    }

    if (isset($body['tags']) && is_string($body['tags'])) {
        $body['tags'] = array_values(array_filter(array_map('trim', explode(',', $body['tags'])), function ($tag) { return $tag !== ''; }));
    }
    return is_array($body) ? $body : null;
}

function request_input_error($fallback = 'bad request') {
    return !empty($GLOBALS['OGI_INPUT_ERROR']) ? (string)$GLOBALS['OGI_INPUT_ERROR'] : $fallback;
}

function bool_value($value, $default = false) {
    if ($value === null || $value === '') return (bool)$default;
    if (is_bool($value)) return $value;
    $parsed = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    return $parsed === null ? (bool)$default : $parsed;
}

function text_lower($value) {
    $value = (string)$value;
    return function_exists('mb_strtolower') ? mb_strtolower($value, 'UTF-8') : strtolower($value);
}

function text_width($value, $width, $suffix = '...') {
    $value = (string)$value;
    if (function_exists('mb_strimwidth')) return mb_strimwidth($value, 0, (int)$width, $suffix, 'UTF-8');
    $chars = preg_split('//u', clean_utf8($value), -1, PREG_SPLIT_NO_EMPTY);
    if (!is_array($chars)) return substr($value, 0, max(0, (int)$width - strlen($suffix))) . $suffix;
    if (count($chars) <= $width) return implode('', $chars);
    return implode('', array_slice($chars, 0, max(0, (int)$width - strlen($suffix)))) . $suffix;
}

function normalize_github_repo($repo) {
    if (!is_string($repo)) return null;
    $repo = trim($repo);
    if ($repo === '') return null;
    if (preg_match('~^https?://github\\.com/([^/?#]+/[^/?#]+?)(?:\\.git)?/?$~i', $repo, $m)) $repo = $m[1];
    $repo = preg_replace('/\\.git$/i', '', $repo);
    if (!preg_match('/^[A-Za-z0-9-]{1,39}\\/[A-Za-z0-9._-]{1,100}$/', $repo)) return null;
    return $repo;
}

function valid_mod_id($id) {
    return is_string($id) && strlen($id) <= 128 && preg_match('/^[A-Za-z0-9_.-]+$/', $id) === 1;
}

function valid_version_string($version) {
    return is_string($version) && strlen($version) <= 100 && preg_match('/^[A-Za-z0-9.+_-]+$/', $version) === 1;
}

function mod_user_can_manage($mod, $username = null) {
    if (is_admin()) return true;
    $username = $username === null ? current_user() : $username;
    if (!is_string($username) || $username === '') return false;
    $developers = is_array($mod['developers'] ?? null) ? $mod['developers'] : [];
    foreach ($developers as $developer) {
        if (is_array($developer) && !empty($developer['username']) && strcasecmp((string)$developer['username'], $username) === 0 && !empty($developer['is_owner'])) return true;
    }
    return false;
}

function next_numeric_id($rows, $field = 'id') {
    $max = 0;
    foreach ((array)$rows as $row) $max = max($max, (int)($row[$field] ?? 0));
    return $max + 1;
}

function current_user() {
    if (!empty($_SESSION['github_user'])) return $_SESSION['github_user'];

    $h = getallheaders_lower();
    if (!empty($h['authorization']) && preg_match('/Bearer\s+(\S+)/i', $h['authorization'], $m)) {
        $token = $m[1];
        $tokens = db_read('tokens.json');
        if (!is_array($tokens)) $tokens = [];
        if (isset($tokens[$token]) && is_array($tokens[$token]) && !empty($tokens[$token]['username'])) {
            if (isset($tokens[$token]['expires_at']) && strtotime($tokens[$token]['expires_at']) < time()) return null;
            return $tokens[$token]['username'];
        }
    }
    return null;
}

function is_admin() {
    global $ADMIN_USERS;
    $u = current_user();
    $admins = is_array($ADMIN_USERS ?? null) ? $ADMIN_USERS : [];
    return $u !== null && in_array($u, $admins, true);
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
    $headers = [];
    if (function_exists('getallheaders')) {
        foreach ((array)getallheaders() as $key => $value) $headers[strtolower((string)$key)] = $value;
    } else {
        foreach ($_SERVER as $name => $value) {
            if (strpos($name, 'HTTP_') === 0) {
                $key = strtolower(str_replace('_', '-', substr($name, 5)));
                $headers[$key] = $value;
            }
        }
        if (isset($_SERVER['CONTENT_TYPE'])) $headers['content-type'] = $_SERVER['CONTENT_TYPE'];
        if (isset($_SERVER['CONTENT_LENGTH'])) $headers['content-length'] = $_SERVER['CONTENT_LENGTH'];
    }
    return $headers;
}

function normalize_version($v) {
    if ($v === null || !is_scalar($v)) return null;
    $s = trim((string)$v);
    if ($s === '') return null;
    return preg_replace('/^v/i', '', $s);
}

function normalize_geode($g) {
    if ($g === null || !is_scalar($g)) return null;
    $s = trim((string)$g);
    return $s === '' ? null : $s;
}

function normalize_gd($gd) {
    if ($gd === null || $gd === '') return null;
    // Older Geode manifests used a global GD version string; newer manifests
    // use a per-platform object. Preserve both formats.
    if (is_string($gd) || is_numeric($gd)) {
        $value = trim((string)$gd);
        return $value === '' ? null : $value;
    }
    if (!is_array($gd)) return null;
    $out = [];
    foreach ($gd as $platform => $value) {
        if (!is_scalar($value)) continue;
        $value = trim((string)$value);
        if ($value === '') continue;
        $out[(string)$platform] = $value;
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

// Returns ['token' => '...'] or ['error' => '...', 'description' => '...', 'raw' => '...']
function github_exchange_code($code) {
    if (!defined('CLIENT_ID') || CLIENT_ID === '') {
        return ['error' => 'config', 'description' => 'CLIENT_ID is not defined in _config.php', 'raw' => null];
    }
    if (!defined('CLIENT_SECRET') || CLIENT_SECRET === '') {
        return ['error' => 'config', 'description' => 'CLIENT_SECRET is not defined in _config.php', 'raw' => null];
    }

    $redirect_uri = defined('CALLBACK_URL') && CALLBACK_URL ? CALLBACK_URL : (current_url_base() . '/callback');

    $post = http_build_query([
        'client_id'     => CLIENT_ID,
        'client_secret' => CLIENT_SECRET,
        'code'          => $code,
        'redirect_uri'  => $redirect_uri,
    ]);

    $opts = [
        'http' => [
            'method'        => 'POST',
            'header'        => "Accept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " . strlen($post) . "\r\n",
            'content'       => $post,
            'timeout'       => 15,
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
    ];

    $res = @file_get_contents('https://github.com/login/oauth/access_token', false, stream_context_create($opts));
    if ($res === false) {
        $last = error_get_last();
        $msg = $last['message'] ?? 'unknown network error';
        api_log('oauth.exchange.fail', ['reason' => 'network', 'msg' => $msg, 'redirect_uri' => $redirect_uri]);
        return ['error' => 'network', 'description' => 'Cannot reach github.com: ' . $msg, 'raw' => null];
    }

    $json = json_decode($res, true);
    if ($json === null) {
        api_log('oauth.exchange.fail', ['reason' => 'bad_json', 'raw' => $res, 'redirect_uri' => $redirect_uri]);
        return ['error' => 'bad_response', 'description' => 'GitHub returned a non-JSON response', 'raw' => $res];
    }

    if (!empty($json['error'])) {
        api_log('oauth.exchange.fail', [
            'reason'       => $json['error'],
            'description'  => $json['error_description'] ?? null,
            'redirect_uri' => $redirect_uri,
        ]);
        return [
            'error'       => $json['error'],
            'description' => $json['error_description'] ?? 'GitHub rejected the token exchange',
            'raw'         => null,
        ];
    }

    if (empty($json['access_token'])) {
        api_log('oauth.exchange.fail', ['reason' => 'no_token', 'raw' => $res, 'redirect_uri' => $redirect_uri]);
        return ['error' => 'no_token', 'description' => 'GitHub did not return an access_token', 'raw' => $res];
    }

    return ['token' => $json['access_token']];
}

function github_get_user($token) {
    if (!is_string($token) || $token === '' || !preg_match('/^[A-Za-z0-9_]+$/', $token)) return null;
    $opts = ['http' => [
        'method'  => 'GET',
        'header'  => "User-Agent: Open-Geode-Index/2.0\r\nAuthorization: Bearer " . $token . "\r\nAccept: application/json\r\n",
        'timeout' => 10,
        'ignore_errors' => true,
    ]];
    $res = @file_get_contents('https://api.github.com/user', false, stream_context_create($opts));
    if ($res === false) return null;
    $decoded = json_decode($res, true);
    return json_last_error() === JSON_ERROR_NONE && is_array($decoded) && empty($decoded['message']) ? $decoded : null;
}

function issue_local_tokens_for_user($username, $tokens_override = null) {
    $tokens = is_array($tokens_override) ? $tokens_override : db_read('tokens.json');
    if (!is_array($tokens)) $tokens = [];
    $access = bin2hex(random_bytes(20));
    $refresh = bin2hex(random_bytes(24));
    $now = time();
    $tokens[$access] = [
        'username'           => (string)$username,
        'issued_at'          => iso8601_utc($now),
        'expires_at'         => iso8601_utc($now + ACCESS_TOKEN_TTL),
        'refresh_token'      => $refresh,
        'refresh_expires_at' => iso8601_utc($now + REFRESH_TOKEN_TTL),
    ];
    if (!db_write('tokens.json', $tokens)) return null;
    return ['access_token' => $access, 'refresh_token' => $refresh];
}

function ensure_developer_record($username, $display = null) {
    $devs = db_read('developers.json');
    if (!is_array($devs)) $devs = [];
    foreach ($devs as $developer) {
        if (is_array($developer) && ($developer['username'] ?? null) === $username) return true;
    }
    $devs[] = ['id' => next_numeric_id($devs), 'username' => $username, 'display_name' => $display ?: $username, 'verified' => false, 'admin' => false, 'github_id' => null];
    return db_write('developers.json', $devs);
}

function current_url_base() {
    if (defined('SITE_URL') && is_string(SITE_URL) && preg_match('#^https?://[A-Za-z0-9.-]+(?::[0-9]+)?$#', rtrim(SITE_URL, '/'))) return rtrim(SITE_URL, '/');
    $host = (string)($_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost'));
    if (!preg_match('/^[A-Za-z0-9.:-]+$/', $host)) $host = (string)($_SERVER['SERVER_NAME'] ?? 'localhost');
    $scheme = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') ? 'https' : 'http';
    return $scheme . '://' . $host;
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
    return rtrim(current_url_base(), '/') . '/v1/mods/' . rawurlencode((string)$modid) . '/versions/' . rawurlencode((string)$version) . '/download';
}

function version_for_public($modid, $v) {
    if (!is_array($v)) return [];
    $out = $v;
    if (isset($out['gd'])) $out['gd'] = expand_gd_platforms($out['gd']);

    if (!empty($v['download_link'])) {
        $out['download_link'] = public_download_link($modid, $v['version']);
        return $out;
    }

    $up = fetch_upstream_json('/v1/mods/' . rawurlencode((string)$modid));
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

function gd_target_is_compatible($target, $client_gd, $platform = null) {
    // No client GD was supplied: preserve unfiltered API behavior.
    if ($client_gd === null || trim((string)$client_gd) === '') return true;
    $client_gd = trim((string)$client_gd);

    // Wildcard explicitly means all GD versions. Missing metadata remains unknown
    // and is not filtered here to avoid hiding legacy mods without a GD field.
    if ($target === null || $target === '' || $target === '*') return true;

    $is_exact_gd = function ($value) use ($client_gd) {
        if ($value === null || $value === '') return false;
        if ($value === '*') return true;
        if (!is_scalar($value)) return false;
        // GD target is a compatibility target, not a minimum-version range.
        return version_compare(trim((string)$value), $client_gd, '==');
    };

    if (is_array($target)) {
        $target = expand_gd_platforms($target);
        if ($platform !== null && $platform !== '') {
            $platform = strtolower(trim((string)$platform));
            $aliases = [
                'windows' => 'win', 'win32' => 'win', 'win64' => 'win',
                'macos' => 'mac', 'osx' => 'mac',
                'android' => 'android', 'android32' => 'android32', 'android64' => 'android64',
                'ios' => 'ios',
            ];
            $platform = $aliases[$platform] ?? $platform;
            if (isset($target[$platform])) return $is_exact_gd($target[$platform]);
            // Expanded platform aliases can be used when the client gives a generic platform.
            if ($platform === 'android' && isset($target['android32'])) return $is_exact_gd($target['android32']) || (isset($target['android64']) && $is_exact_gd($target['android64']));
            if ($platform === 'mac' && isset($target['mac-intel'])) return $is_exact_gd($target['mac-intel']) || (isset($target['mac-arm']) && $is_exact_gd($target['mac-arm']));
            return false;
        }
        // If the client did not identify a platform, compatible if at least
        // one explicitly declared platform target exactly matches this GD.
        foreach ($target as $value) if ($is_exact_gd($value)) return true;
        return false;
    }

    return $is_exact_gd($target);
}

function filter_mod_for_client_gd($mod, $client_gd = null, $platform = null) {
    if (!is_array($mod)) return null;
    if ($client_gd === null || $client_gd === '') return $mod;
    if (empty($mod['versions']) || !is_array($mod['versions'])) {
        return gd_target_is_compatible($mod['gd'] ?? null, $client_gd, $platform) ? $mod : null;
    }

    $compatible = [];
    foreach ($mod['versions'] as $version) {
        if (!is_array($version)) continue;
        if (gd_target_is_compatible($version['gd'] ?? ($mod['gd'] ?? null), $client_gd, $platform)) {
            $compatible[] = $version;
        }
    }
    if (!$compatible) return null;

    // Version arrays are stored newest-first; keep their original ordering.
    $mod['versions'] = $compatible;
    $mod['gd'] = $compatible[0]['gd'] ?? ($mod['gd'] ?? null);
    return $mod;
}

function mod_for_public($mod) {
    if (!is_array($mod) || empty($mod['id'])) return $mod;
    $out = $mod;
    if (!empty($out['versions']) && is_array($out['versions'])) {
        $arr = [];
        foreach ($out['versions'] as $v) if (is_array($v)) $arr[] = version_for_public($out['id'], $v);
        $out['versions'] = $arr;
    }
    return $out;
}

// [PATCH] upstream cache for 5 minutes; the upstream host is server-configured only.
function fetch_upstream_json($path, $query = [], $ttl = UPSTREAM_CACHE_TTL) {
    $base = defined('UPSTREAM_URL') ? rtrim((string)UPSTREAM_URL, '/') : 'https://api.geode-sdk.org';
    if (!is_safe_url($base)) return null;
    $url = $base . '/' . ltrim((string)$path, '/');
    if (!empty($query)) $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($query);

    $cache_dir = DATA_DIR . '/cache';
    $use_cache = (int)$ttl > 0;
    $cache_file = $cache_dir . '/' . md5($url) . '.json';
    if ($use_cache && is_file($cache_file) && (time() - filemtime($cache_file)) < (int)$ttl) {
        $cached = @file_get_contents($cache_file);
        if ($cached !== false) {
            $decoded = json_decode($cached, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) return $decoded;
        }
    }

    $remote = open_remote_stream($url, 20, 5);
    if ($remote === null) return null;
    $res = @stream_get_contents($remote['stream'], 8 * 1024 * 1024 + 1);
    fclose($remote['stream']);
    if (!is_string($res) || strlen($res) > 8 * 1024 * 1024) return null;

    $decoded = json_decode($res, true);
    if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) return null;
    if ($use_cache && (!isset($decoded['error']) || $decoded['error'] === '')) {
        if (!is_dir($cache_dir)) @mkdir($cache_dir, 0700, true);
        if (is_dir($cache_dir) && is_writable($cache_dir)) @file_put_contents($cache_file, $res, LOCK_EX);
    }
    return $decoded;
}

function resolve_final_url($url, $max_redirects = 8, $timeout = 8) {
    if (!is_safe_url($url)) return ['url' => null, 'code' => null];
    $remote = open_remote_stream($url, $timeout, $max_redirects);
    if ($remote === null) return ['url' => null, 'code' => null];
    $result = ['url' => $remote['url'], 'code' => $remote['status']];
    fclose($remote['stream']);
    return $result;
}

function iso8601_utc($ts = null) {
    if ($ts === null) $ts = time();
    return gmdate('Y-m-d\TH:i:s\Z', (int)$ts);
}

function fetch_github_raw_json($repo, $path, $ref = 'HEAD') {
    $ref = trim((string)$ref);
    if ($ref === '' || preg_match('/[\x00-\x20\x7f]/', $ref)) return null;
    $url = "https://raw.githubusercontent.com/{$repo}/" . rawurlencode($ref) . "/{$path}";
    $opts = ['http' => ['method' => 'GET', 'header' => "User-Agent: Open-Geode-Index\r\nAccept: application/json\r\n", 'timeout' => 8]];
    $res = @file_get_contents($url, false, stream_context_create($opts));
    if ($res === false) return null;
    $decoded = json_decode($res, true);
    return json_last_error() === JSON_ERROR_NONE && is_array($decoded) ? $decoded : null;
}

function fetch_github_raw_text($repo, $path, $ref = 'HEAD') {
    $ref = trim((string)$ref);
    if ($ref === '' || preg_match('/[\x00-\x20\x7f]/', $ref)) return null;
    $url = "https://raw.githubusercontent.com/{$repo}/" . rawurlencode($ref) . "/{$path}";
    $opts = ['http' => ['method' => 'GET', 'header' => "User-Agent: Open-Geode-Index\r\nAccept: text/plain\r\n", 'timeout' => 8]];
    $res = @file_get_contents($url, false, stream_context_create($opts));
    return $res === false ? null : $res;
}

/* ======================= API: tags ======================= */

function api_tags_index() {
    $tags = db_read('tags.json');
    if (!is_array($tags)) $tags = [];
    $names = [];
    foreach ($tags as $t) $names[] = is_array($t) && isset($t['name']) ? $t['name'] : (string)$t;
    json_response_etag(['error' => '', 'payload' => $names], 200, 300);
}

function api_tags_detailed() {
    $tags = db_read('tags.json');
    if (!is_array($tags)) $tags = [];
    json_response_etag(['error' => '', 'payload' => $tags], 200, 300);
}

/* ======================= API: developers ======================= */

function api_developers_index() {
    $q = $_GET;
    $devs = db_read('developers.json');
    if (!is_array($devs)) $devs = [];

    if (!empty($q['query']) && is_scalar($q['query'])) {
        $qq = text_lower($q['query']);
        $devs = array_values(array_filter($devs, function ($d) use ($qq) {
            return is_array($d) && ((strpos(text_lower($d['username'] ?? ''), $qq) !== false) || (strpos(text_lower($d['display_name'] ?? ''), $qq) !== false));
        }));
    }

    $page = isset($q['page']) && is_scalar($q['page']) ? max(1, min(100000, (int)$q['page'])) : 1;
    $per_page = isset($q['per_page']) && is_scalar($q['per_page']) ? max(1, min(200, (int)$q['per_page'])) : 50;
    $count = count($devs);
    $data = array_slice($devs, ($page - 1) * $per_page, $per_page);
    json_response(['error' => '', 'payload' => ['data' => $data, 'count' => $count]]);
}

function api_developers_get($id) {
    $devs = db_read('developers.json') ?: [];
    foreach ($devs as $d) if (is_array($d) && (int)($d['id'] ?? 0) === $id) return json_response(['error' => '', 'payload' => $d]);
    json_response(['error' => 'Developer not found', 'payload' => null], 404);
}

function api_developers_update($id) {
    if (!require_admin()) return;
    $body = json_input();
    if (!is_array($body) || !$body) return json_response(['error' => request_input_error('bad request'), 'payload' => null], 400);

    $devs = db_read('developers.json');
    if (!is_array($devs)) $devs = [];
    foreach ($devs as $i => $d) {
        if (is_array($d) && (int)($d['id'] ?? 0) === $id) {
            if (array_key_exists('admin', $body))    $devs[$i]['admin'] = bool_value($body['admin']);
            if (array_key_exists('verified', $body)) $devs[$i]['verified'] = bool_value($body['verified']);
            if (!db_write('developers.json', $devs)) return json_response(['error' => 'Could not save developer changes', 'payload' => null], 500);
            api_log('developer.update', ['id' => $id]);
            return json_response(['error' => '', 'payload' => $devs[$i]]);
        }
    }
    json_response(['error' => 'Developer not found', 'payload' => null], 404);
}

/* ======================= API: auth ======================= */

function api_login_github() {
    if (!defined('CLIENT_ID') || CLIENT_ID === '') return json_response(['error' => 'GitHub OAuth CLIENT_ID is not configured', 'payload' => null], 503);
    $state = bin2hex(random_bytes(24));
    $_SESSION['oauth_state'] = $state;
    $redirect = defined('CALLBACK_URL') && CALLBACK_URL ? CALLBACK_URL : current_url_base() . '/callback';
    $params = http_build_query(['client_id' => CLIENT_ID, 'redirect_uri' => $redirect, 'scope' => 'read:user', 'state' => $state]);
    json_response(['error' => '', 'payload' => "https://github.com/login/oauth/authorize?$params"]);
}

function api_login_github_web() { return api_login_github(); }

function api_login_callback() {
    $body = json_input() ?: $_REQUEST;

    if (empty($body['code']) || empty($body['state'])) {
        return render_oauth_error(
            'Bad request',
            'The callback did not contain the "code" or "state" parameter.',
            ['query' => $_GET, 'request_keys' => array_keys($_REQUEST)]
        );
    }

    if (!isset($_SESSION['oauth_state']) || !hash_equals($_SESSION['oauth_state'], (string)$body['state'])) {
        return render_oauth_error(
            'Invalid state',
            'The CSRF state does not match. The authorization flow may have been started in another browser tab or the session expired.',
            ['sent_state' => $body['state'], 'session_state_present' => isset($_SESSION['oauth_state'])]
        );
    }

    // Code is single-use — drop the state now to avoid bad_verification_code on resubmit
    unset($_SESSION['oauth_state']);

    $ex = github_exchange_code($body['code']);
    if (isset($ex['error'])) {
        return render_oauth_error('Failed to obtain access token', $ex['description'], [
            'github_error' => $ex['error'],
            'redirect_uri' => defined('CALLBACK_URL') && CALLBACK_URL ? CALLBACK_URL : (current_url_base() . '/callback'),
            'raw'          => $ex['raw'] ?? null,
        ]);
    }
    $token = $ex['token'];

    $user = github_get_user($token);
    if (!$user || empty($user['login'])) {
        return render_oauth_error(
            'Failed to fetch GitHub user',
            'The token exchange succeeded but the request to api.github.com/user failed. Possibly a rate limit or network issue.',
            ['token_present' => true]
        );
    }

    $_SESSION['github_user']  = $user['login'];
    $_SESSION['github_token'] = $token;
    if (!ensure_developer_record($user['login'], $user['name'] ?? $user['login'])) {
        return render_oauth_error('Login failed', 'Could not save the developer profile. Check data directory permissions.', []);
    }
    $local = issue_local_tokens_for_user($user['login']);
    if (!$local) return render_oauth_error('Login failed', 'Could not save local access tokens. Check data directory permissions.', []);
    api_log('login.callback', ['user' => $user['login']]);

    render_oauth_success($user['login'], $local);
}

function api_login_github_poll() {
    json_response(['error' => 'not implemented', 'payload' => null], 501);
}

function api_login_github_token() {
    $body = json_input();
    if (!is_array($body) || empty($body['token'])) return json_response(['error' => request_input_error('token is required'), 'payload' => null], 400);

    $user = github_get_user($body['token']);
    if (!$user || empty($user['login'])) return json_response(['error' => 'invalid access token', 'payload' => null], 400);

    if (!ensure_developer_record($user['login'], $user['name'] ?? $user['login'])) return json_response(['error' => 'Could not save developer profile', 'payload' => null], 500);
    $local = issue_local_tokens_for_user($user['login']);
    if (!$local) return json_response(['error' => 'Could not save local access tokens', 'payload' => null], 500);
    json_response(['error' => '', 'payload' => $local]);
}

function api_refresh_token() {
    $body = json_input();
    if (!is_array($body) || empty($body['refresh_token']) || !is_string($body['refresh_token'])) {
        return json_response(['error' => request_input_error('refresh_token is required'), 'payload' => null], 400);
    }

    $refresh = $body['refresh_token'];
    $tokens = db_read('tokens.json');
    if (!is_array($tokens)) $tokens = [];
    foreach ($tokens as $access_token => $meta) {
        if (!is_array($meta) || empty($meta['refresh_token']) || !hash_equals((string)$meta['refresh_token'], $refresh)) continue;
        $expires = isset($meta['refresh_expires_at']) ? strtotime((string)$meta['refresh_expires_at']) : false;
        if ($expires === false || $expires < time()) {
            unset($tokens[$access_token]);
            db_write('tokens.json', $tokens);
            return json_response(['error' => 'invalid or expired refresh token', 'payload' => null], 401);
        }
        $username = (string)($meta['username'] ?? '');
        if ($username === '') return json_response(['error' => 'invalid refresh token', 'payload' => null], 401);
        unset($tokens[$access_token]);
        $new_tokens = issue_local_tokens_for_user($username, $tokens);
        if (!$new_tokens) return json_response(['error' => 'could not rotate token', 'payload' => null], 500);
        return json_response(['error' => '', 'payload' => $new_tokens]);
    }
    json_response(['error' => 'invalid or expired refresh token', 'payload' => null], 401);
}

/* ======================= API: me ======================= */

function api_get_me() {
    if (!require_auth()) return;
    $u = current_user();
    $devs = db_read('developers.json');
    if (!is_array($devs)) $devs = [];
    foreach ($devs as $d) if (is_array($d) && ($d['username'] ?? null) === $u) return json_response(['error' => '', 'payload' => $d]);
    json_response(['error' => '', 'payload' => ['id' => null, 'username' => $u, 'display_name' => $u, 'verified' => false, 'admin' => is_admin(), 'github_id' => null]]);
}

function api_put_me() {
    if (!require_auth()) return;
    $u = current_user();
    $body = json_input();
    if (!is_array($body) || !$body) return json_response(['error' => request_input_error('bad request'), 'payload' => null], 400);

    $devs = db_read('developers.json') ?: [];
    foreach ($devs as $i => $d) {
        if (($d['username'] ?? null) === $u) {
            if (isset($body['display_name'])) {
                if (!is_scalar($body['display_name'])) return json_response(['error' => 'display_name must be text', 'payload' => null], 400);
                $name = trim((string)$body['display_name']);
                if ($name === '' || strlen($name) > 128) return json_response(['error' => 'display_name must be between 1 and 128 bytes', 'payload' => null], 400);
                $devs[$i]['display_name'] = clean_utf8($name);
            }
            if (!db_write('developers.json', $devs)) return json_response(['error' => 'Could not save profile changes', 'payload' => null], 500);
            return json_response(['error' => '', 'payload' => $devs[$i]]);
        }
    }

    $new = ['id' => next_numeric_id($devs), 'username' => $u, 'display_name' => isset($body['display_name']) && is_scalar($body['display_name']) ? text_width(trim((string)$body['display_name']), 64, '') : $u, 'verified' => false, 'admin' => false, 'github_id' => null];
    $devs[] = $new;
    if (!db_write('developers.json', $devs)) return json_response(['error' => 'Could not create profile', 'payload' => null], 500);
    json_response(['error' => '', 'payload' => $new]);
}

function api_get_own_mods() {
    if (!require_auth()) return;
    $u = current_user();
    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    $own = array_values(array_filter($mods, function ($m) use ($u) {
        if (!is_array($m)) return false;
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
            if (!db_write('tokens.json', $tokens)) return json_response(['error' => 'Could not revoke token', 'payload' => null], 500);
            return json_response(['error' => '', 'payload' => null], 204);
        }
        return json_response(['error' => 'not found', 'payload' => null], 404);
    }
    json_response(['error' => '', 'payload' => null], 204);
}

function api_delete_tokens() {
    if (!require_auth()) return;
    $u = current_user();
    $tokens = db_read('tokens.json');
    if (!is_array($tokens)) $tokens = [];
    foreach ($tokens as $k => $meta) if (is_array($meta) && ($meta['username'] ?? null) === $u) unset($tokens[$k]);
    if (!db_write('tokens.json', $tokens)) return json_response(['error' => 'Could not revoke tokens', 'payload' => null], 500);
    json_response(['error' => '', 'payload' => null], 204);
}

/* ======================= API: loader versions ======================= */

function api_loader_versions_index() {
    $q = $_GET;
    $all = db_read('loader_versions.json');
    if (!is_array($all)) $all = [];

    if (isset($q['prerelease']) && is_scalar($q['prerelease'])) {
        $pr = filter_var($q['prerelease'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($pr !== null) $all = array_values(array_filter($all, fn($v) => is_array($v) && bool_value($v['prerelease'] ?? false) === $pr));
    }
    if (!empty($q['gd']) && is_scalar($q['gd'])) {
        $gd = (string)$q['gd'];
        $all = array_values(array_filter($all, fn($v) => is_array($v) && !empty($v['gd']) && (is_string($v['gd']) ? strpos($v['gd'], $gd) !== false : (is_array($v['gd']) && in_array($gd, $v['gd'], true)))));
    }

    $page = isset($q['page']) && is_scalar($q['page']) ? max(1, min(100000, (int)$q['page'])) : 1;
    $per_page = isset($q['per_page']) && is_scalar($q['per_page']) ? max(1, min(200, (int)$q['per_page'])) : 50;
    $count = count($all);
    json_response(['error' => '', 'payload' => ['data' => array_slice($all, ($page - 1) * $per_page, $per_page), 'count' => $count]]);
}

function api_loader_versions_create() {
    if (!require_admin()) return;
    $body = json_input();
    if (!is_array($body) || !isset($body['tag'], $body['commit_hash'], $body['gd']) || !is_scalar($body['tag']) || !is_scalar($body['commit_hash']) || !is_scalar($body['gd'])) {
        return json_response(['error' => request_input_error('tag, commit_hash and gd are required'), 'payload' => null], 400);
    }
    $tag = trim((string)$body['tag']);
    $commit = trim((string)$body['commit_hash']);
    $gd = trim((string)$body['gd']);
    if ($tag === '' || strlen($tag) > 100 || !preg_match('/^[A-Za-z0-9.+_-]+$/', $tag)) return json_response(['error' => 'Invalid loader tag', 'payload' => null], 400);
    if (!preg_match('/^[a-fA-F0-9]{7,64}$/', $commit)) return json_response(['error' => 'commit_hash must be a 7-64 character hexadecimal SHA', 'payload' => null], 400);
    if ($gd === '' || strlen($gd) > 64) return json_response(['error' => 'Invalid GD version', 'payload' => null], 400);

    $all = db_read('loader_versions.json');
    if (!is_array($all)) $all = [];
    foreach ($all as $existing) if (is_array($existing) && (($existing['tag'] ?? null) === $tag || ($existing['version'] ?? null) === $tag)) return json_response(['error' => 'loader version already exists', 'payload' => null], 409);
    $v = [
        'version'     => $tag,
        'tag'         => $tag,
        'gd'          => $gd,
        'prerelease'  => bool_value($body['prerelease'] ?? false),
        'commit_hash' => strtolower($commit),
        'created_at'  => iso8601_utc(),
    ];
    array_unshift($all, $v);
    if (!db_write('loader_versions.json', $all)) return json_response(['error' => 'Could not save loader version', 'payload' => null], 500);
    api_log('loader.create', ['tag' => $body['tag']]);
    json_response(['error' => '', 'payload' => $v], 201);
}

function api_loader_versions_get($version) {
    $all = db_read('loader_versions.json');
    if (!is_array($all)) $all = [];
    foreach ($all as $v) if (is_array($v) && (($v['version'] ?? null) === $version || ($v['tag'] ?? null) === $version)) return json_response(['error' => '', 'payload' => $v]);
    json_response(['error' => 'not found', 'payload' => null], 404);
}

/* ======================= API: mods ======================= */

function api_mods_index() {
    $q = $_GET;
    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    $mods = array_values(array_filter($mods, 'is_array'));

    $client_gd = isset($q['gd']) && is_scalar($q['gd']) && (string)$q['gd'] !== '' ? (string)$q['gd'] : null;
    $client_platform = isset($q['platform']) && is_scalar($q['platform']) ? (string)$q['platform'] : (isset($q['platforms']) && is_scalar($q['platforms']) ? (string)$q['platforms'] : null);
    if ($client_gd !== null) {
        $mods = array_values(array_filter(array_map(function ($mod) use ($client_gd, $client_platform) {
            return filter_mod_for_client_gd($mod, $client_gd, $client_platform);
        }, $mods)));
    }

    if (!empty($q['query']) && is_scalar($q['query'])) {
        $needle = text_lower(trim((string)$q['query']));
        if ($needle !== '') {
            $mods = array_values(array_filter($mods, function ($mod) use ($needle) {
                $tags = is_array($mod['tags'] ?? null) ? array_filter($mod['tags'], 'is_scalar') : [];
                $version_name = '';
                if (!empty($mod['versions'][0]['name'])) $version_name = (string)$mod['versions'][0]['name'];
                $haystack = text_lower(implode(' ', [(string)($mod['id'] ?? ''), $version_name, (string)($mod['about'] ?? ''), implode(' ', array_map('strval', $tags))]));
                return strpos($haystack, $needle) !== false;
            }));
        }
    }

    if (!empty($q['tags']) && is_scalar($q['tags'])) {
        $wanted = array_values(array_filter(array_map('trim', explode(',', (string)$q['tags'])), function ($tag) { return $tag !== ''; }));
        if ($wanted) {
            $mods = array_values(array_filter($mods, function ($mod) use ($wanted) {
                $tags = is_array($mod['tags'] ?? null) ? $mod['tags'] : [];
                foreach ($wanted as $tag) if (!in_array($tag, $tags, true)) return false;
                return true;
            }));
        }
    }

    if (isset($q['featured']) && is_scalar($q['featured'])) {
        $featured = filter_var($q['featured'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($featured !== null) $mods = array_values(array_filter($mods, function ($mod) use ($featured) { return !empty($mod['featured']) === $featured; }));
    }

    $sort = isset($q['sort']) && is_scalar($q['sort']) ? (string)$q['sort'] : 'downloads';
    $timestamp = function ($value) { $time = empty($value) ? 0 : @strtotime((string)$value); return $time === false ? 0 : $time; };
    usort($mods, function ($a, $b) use ($sort, $timestamp) {
        $tie = function () use ($a, $b, $timestamp) {
            $updated = $timestamp($b['updated_at'] ?? null) <=> $timestamp($a['updated_at'] ?? null);
            return $updated !== 0 ? $updated : strcasecmp((string)($a['id'] ?? ''), (string)($b['id'] ?? ''));
        };
        switch ($sort) {
            case 'recently_updated': return $timestamp($b['updated_at'] ?? null) <=> $timestamp($a['updated_at'] ?? null) ?: $tie();
            case 'recently_published': return $timestamp($b['created_at'] ?? null) <=> $timestamp($a['created_at'] ?? null) ?: $tie();
            case 'oldest': return $timestamp($a['created_at'] ?? null) <=> $timestamp($b['created_at'] ?? null) ?: $tie();
            case 'name': return strcasecmp((string)($a['id'] ?? ''), (string)($b['id'] ?? '')) ?: $tie();
            case 'name_reverse': return strcasecmp((string)($b['id'] ?? ''), (string)($a['id'] ?? '')) ?: $tie();
            case 'downloads':
            default: return ((int)($b['download_count'] ?? 0) <=> (int)($a['download_count'] ?? 0)) ?: $tie();
        }
    });

    $page = isset($q['page']) && is_scalar($q['page']) ? max(1, min(100000, (int)$q['page'])) : 1;
    $per_page = isset($q['per_page']) && is_scalar($q['per_page']) ? max(1, min(200, (int)$q['per_page'])) : 50;
    $count = count($mods);
    $slice = array_slice($mods, ($page - 1) * $per_page, $per_page);
    $public = [];
    foreach ($slice as $mod) $public[] = mod_for_public($mod);
    json_response(['error' => '', 'payload' => ['data' => $public, 'count' => $count]]);
}

function is_browser_form_request() {
    if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'POST') return false;
    $mode = strtolower((string)($_SERVER['HTTP_SEC_FETCH_MODE'] ?? ''));
    $dest = strtolower((string)($_SERVER['HTTP_SEC_FETCH_DEST'] ?? ''));
    if ($mode === 'navigate' || $dest === 'document') return true;
    $accept = strtolower((string)($_SERVER['HTTP_ACCEPT'] ?? ''));
    return strpos($accept, 'text/html') !== false && strpos($accept, 'application/json') === false;
}

function publish_form_response($response, $status = 200) {
    if (is_browser_form_request()) {
        $error = is_array($response) ? (string)($response['error'] ?? '') : 'Unknown publishing response';
        $payload = is_array($response['payload'] ?? null) ? $response['payload'] : [];
        if ($error !== '') {
            $flash = ['type' => 'danger', 'message' => $error];
        } elseif (($payload['metadata_source'] ?? '') === 'github_repository') {
            $flash = ['type' => 'warning', 'message' => 'Mod published. Metadata and SHA-256 were recovered from GitHub release information.'];
        } else {
            $flash = ['type' => 'success', 'message' => 'Mod published successfully. The .geode archive was inspected and its SHA-256 was calculated.'];
        }
        $_SESSION['ogi_publish_flash'] = $flash;
        header('Location: /ui', true, 303);
        exit;
    }
    return json_response($response, $status);
}

function api_mods_create() {
    if (!require_auth()) return;
    $user = current_user();
    $body = json_input();
    if (!is_array($body) || !$body) return publish_form_response(['error' => request_input_error('bad request - empty body'), 'payload' => null], 400);

    if (!isset($body['download_link']) || !is_scalar($body['download_link'])) return publish_form_response(['error' => 'download_link is required and must be text', 'payload' => null], 400);
    $download_link = trim((string)$body['download_link']);
    if ($download_link === '') return publish_form_response(['error' => 'download_link is required', 'payload' => null], 400);
    if (!is_safe_url($download_link)) return publish_form_response(['error' => 'download_link must be a public HTTP(S) URL', 'payload' => null], 400);

    $repo = normalize_github_repo($body['repo'] ?? '');
    if (!empty($body['repo']) && $repo === null) return publish_form_response(['error' => 'repo must be a valid GitHub owner/repository path', 'payload' => null], 400);

    $inspection = inspect_remote_geode_with_repo_fallback($download_link, $repo);
    if (!empty($inspection['error'])) {
        $status = strpos($inspection['error'], 'ZipArchive') !== false ? 503 : 400;
        return publish_form_response(['error' => $inspection['error'], 'payload' => null], $status);
    }
    $metadata = $inspection['metadata'];
    $modjson = $metadata['modjson'];

    $mod_id = !empty($modjson['id']) && is_scalar($modjson['id']) ? (string)$modjson['id'] : $repo;
    if (!valid_mod_id($mod_id)) return publish_form_response(['error' => 'The mod.json id is missing or invalid', 'payload' => null], 400);

    $mod_name = !empty($modjson['name']) && is_scalar($modjson['name']) ? clean_utf8((string)$modjson['name']) : $mod_id;
    $mod_tags = [];
    if (isset($modjson['tags']) && is_array($modjson['tags'])) {
        foreach ($modjson['tags'] as $tag) if (is_string($tag) && trim($tag) !== '') $mod_tags[] = text_width(trim($tag), 48, '');
    }
    $initial_version = normalize_version($body['version'] ?? ($modjson['version'] ?? null)) ?: '1.0.0';
    if (!valid_version_string($initial_version)) return publish_form_response(['error' => 'Invalid version string in request or mod.json', 'payload' => null], 400);

    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    foreach ($mods as $existing) if (is_array($existing) && ($existing['id'] ?? null) === $mod_id) {
        return publish_form_response(['error' => 'mod already exists (by id)', 'payload' => null], 409);
    }

    $now = iso8601_utc();
    $geode_value = isset($modjson['geode']) ? normalize_geode($modjson['geode']) : null;
    $gd_value = isset($modjson['gd']) ? normalize_gd($modjson['gd']) : null;
    $version_entry = [
        'name' => $mod_name,
        'version' => $initial_version,
        'download_link' => $download_link,
        'hash' => $inspection['hash'] ?? null,
        'metadata_source' => $inspection['metadata_source'] ?? 'geode_archive',
        'metadata_warning' => $inspection['metadata_warning'] ?? null,
        'geode' => $geode_value,
        'download_count' => 0,
        'early_load' => bool_value($body['early_load'] ?? null),
        'requires_patching' => bool_value($body['requires_patching'] ?? null),
        'api' => bool_value($modjson['api'] ?? ($body['api'] ?? false)),
        'mod_id' => $mod_id,
        'gd' => expand_gd_platforms($gd_value),
        'status' => 'accepted',
        'description' => isset($modjson['description']) && is_scalar($modjson['description']) ? clean_utf8((string)$modjson['description']) : null,
        'created_at' => $now,
        'updated_at' => $now,
    ];

    $repository_url = $repo ? 'https://github.com/' . $repo : null;
    $logo_url = null;
    if (!empty($modjson['logo_url']) && is_string($modjson['logo_url']) && is_safe_url($modjson['logo_url'])) $logo_url = $modjson['logo_url'];
    elseif ($repo) $logo_url = 'https://raw.githubusercontent.com/' . $repo . '/HEAD/logo.png';

    $developers = !empty($modjson['developers']) && is_array($modjson['developers'])
        ? map_modjson_developers($modjson['developers'], $user)
        : map_modjson_developers([], $user);

    $mod = [
        'id' => $mod_id,
        'about' => $metadata['about'] ?? null,
        'changelog' => $metadata['changelog'] ?? null,
        'metadata_source' => $inspection['metadata_source'] ?? 'geode_archive',
        'metadata_warning' => $inspection['metadata_warning'] ?? null,
        'created_at' => $now,
        'updated_at' => $now,
        'developers' => $developers,
        'download_count' => 0,
        'featured' => bool_value($body['featured'] ?? false) && is_admin(),
        'tags' => array_values(array_unique($mod_tags)),
        'versions' => [$version_entry],
        'repo' => $repo,
        'repository' => $repository_url,
        'logo_url' => $logo_url,
        'links' => isset($modjson['links']) && is_array($modjson['links']) ? $modjson['links'] : null,
        'submitted_by' => $user,
    ];

    $mods[] = $mod;
    if (!db_write('mods.json', $mods)) return publish_form_response(['error' => 'Could not save mod: data directory is not writable', 'payload' => null], 500);
    api_log('mod.create', ['id' => $mod_id, 'version' => $initial_version]);
    publish_form_response(['error' => '', 'payload' => mod_for_public($mod)], 201);
}

function api_mods_get($id) {
    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    foreach ($mods as $m) {
        if (!is_array($m) || ($m['id'] ?? null) !== $id) continue;
        $client_gd = isset($_GET['gd']) && is_scalar($_GET['gd']) && $_GET['gd'] !== '' ? (string)$_GET['gd'] : null;
        $client_platform = isset($_GET['platform']) && is_scalar($_GET['platform']) ? (string)$_GET['platform'] : (isset($_GET['platforms']) && is_scalar($_GET['platforms']) ? (string)$_GET['platforms'] : null);
        $filtered = filter_mod_for_client_gd($m, $client_gd, $client_platform);
        if ($filtered === null) return json_response(['error' => 'mod not found for this GD version', 'payload' => null], 404);
        $m = $filtered;

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
        if ($up && isset($up['error']) && $up['error'] === '' && isset($up['payload']) && is_array($up['payload'])) {
            $client_gd = isset($_GET['gd']) && is_scalar($_GET['gd']) && $_GET['gd'] !== '' ? (string)$_GET['gd'] : null;
            $client_platform = isset($_GET['platform']) && is_scalar($_GET['platform']) ? (string)$_GET['platform'] : (isset($_GET['platforms']) && is_scalar($_GET['platforms']) ? (string)$_GET['platforms'] : null);
            $filtered = filter_mod_for_client_gd($up['payload'], $client_gd, $client_platform);
            if ($filtered === null) return json_response(['error' => 'mod not found for this GD version', 'payload' => null], 404);
            return json_response(['error' => '', 'payload' => $filtered]);
        }
        if ($up === null) return json_response(['error' => 'upstream unavailable', 'payload' => null], 502);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mods_update_admin($id) {
    if (!require_admin()) return;
    $body = json_input();
    if (!is_array($body) || !$body) return json_response(['error' => request_input_error('bad request'), 'payload' => null], 400);

    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    foreach ($mods as $i => $mod) {
        if (!is_array($mod) || ($mod['id'] ?? null) !== $id) continue;
        if (array_key_exists('featured', $body)) $mods[$i]['featured'] = bool_value($body['featured']);
        if (array_key_exists('about', $body)) {
            if (!is_scalar($body['about'])) return json_response(['error' => 'about must be text', 'payload' => null], 400);
            $mods[$i]['about'] = clean_utf8((string)$body['about']);
        }
        $mods[$i]['updated_at'] = iso8601_utc();
        if (!db_write('mods.json', $mods)) return json_response(['error' => 'Could not save mod changes', 'payload' => null], 500);
        return json_response(['error' => '', 'payload' => mod_for_public($mods[$i])], 200);
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

function api_mods_update_owner($id) {
    if (!require_auth()) return;
    $user = current_user();
    $body = json_input();
    if (!is_array($body) || !$body) return json_response(['error' => request_input_error('bad request - empty body'), 'payload' => null], 400);

    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    foreach ($mods as $i => $mod) {
        if (!is_array($mod) || ($mod['id'] ?? null) !== $id) continue;
        if (!mod_user_can_manage($mod, $user)) return json_response(['error' => 'forbidden - only owner or admin can update', 'payload' => null], 403);

        if (array_key_exists('tags', $body)) {
            $tags = $body['tags'];
            if (is_string($tags)) $tags = explode(',', $tags);
            if (!is_array($tags)) return json_response(['error' => 'tags must be an array or comma-separated string', 'payload' => null], 400);
            $clean_tags = [];
            foreach ($tags as $tag) if (is_scalar($tag) && trim((string)$tag) !== '') $clean_tags[] = text_width(trim((string)$tag), 48, '');
            $mods[$i]['tags'] = array_values(array_unique($clean_tags));
        }

        if (isset($body['owner_display_name'])) {
            if (!is_scalar($body['owner_display_name'])) return json_response(['error' => 'owner_display_name must be text', 'payload' => null], 400);
            $new_name = trim((string)$body['owner_display_name']);
            if (strlen($new_name) > 128) return json_response(['error' => 'owner display name is too long', 'payload' => null], 400);
            if ($new_name !== '' && !empty($mods[$i]['developers']) && is_array($mods[$i]['developers'])) {
                $updated = false;
                foreach ($mods[$i]['developers'] as $developer_index => $developer) {
                    if (!empty($developer['is_owner'])) {
                        $mods[$i]['developers'][$developer_index]['display_name'] = clean_utf8($new_name);
                        $updated = true;
                        break;
                    }
                }
                if (!$updated && count($mods[$i]['developers']) > 0) $mods[$i]['developers'][0]['display_name'] = clean_utf8($new_name);
            }
        }

        if (array_key_exists('prefer_github_info', $body)) $mods[$i]['prefer_github_info'] = bool_value($body['prefer_github_info']);
        if (array_key_exists('about', $body)) {
            if (!is_scalar($body['about'])) return json_response(['error' => 'about must be text', 'payload' => null], 400);
            $mods[$i]['about'] = clean_utf8((string)$body['about']);
        }
        if (array_key_exists('changelog', $body)) {
            if (!is_scalar($body['changelog'])) return json_response(['error' => 'changelog must be text', 'payload' => null], 400);
            $mods[$i]['changelog'] = clean_utf8((string)$body['changelog']);
        }
        if (array_key_exists('logo_url', $body)) {
            if (!is_scalar($body['logo_url'])) return json_response(['error' => 'logo_url must be text', 'payload' => null], 400);
            $logo = trim((string)$body['logo_url']);
            if ($logo !== '' && !is_safe_url($logo)) return json_response(['error' => 'logo_url must be a public HTTP(S) URL', 'payload' => null], 400);
            $mods[$i]['logo_url'] = $logo !== '' ? $logo : null;
        }
        if (isset($body['links'])) {
            if (!is_array($body['links'])) return json_response(['error' => 'links must be an object or array', 'payload' => null], 400);
            $mods[$i]['links'] = $body['links'];
        }

        $new_metadata = null;
        if (isset($body['download_link']) && !is_scalar($body['download_link'])) return json_response(['error' => 'download_link must be text', 'payload' => null], 400);
        $download_link = trim((string)($body['download_link'] ?? ''));
        if ($download_link !== '') {
            if (!is_safe_url($download_link)) return json_response(['error' => 'download_link must be a public HTTP(S) URL', 'payload' => null], 400);
            $inspection = inspect_remote_geode_with_repo_fallback($download_link, $mods[$i]['repo'] ?? null);
            if (!empty($inspection['error'])) {
                $status = strpos($inspection['error'], 'ZipArchive') !== false ? 503 : 400;
                return json_response(['error' => $inspection['error'], 'payload' => null], $status);
            }
            $new_metadata = $inspection['metadata'];
            $inner = $new_metadata['modjson'];
            if (!empty($inner['id']) && (string)$inner['id'] !== (string)$id) {
                return json_response(['error' => 'mod id inside .geode does not match existing mod id', 'payload' => null], 400);
            }

            $version = normalize_version($body['version'] ?? ($inner['version'] ?? null)) ?: date('YmdHis');
            if (!valid_version_string($version)) return json_response(['error' => 'Invalid version string', 'payload' => null], 400);
            $now = iso8601_utc();
            $new_version = [
                'name' => isset($inner['name']) && is_scalar($inner['name']) ? clean_utf8((string)$inner['name']) : (string)($body['name'] ?? ($mods[$i]['repo'] ?? $id)),
                'version' => $version,
                'download_link' => $download_link,
                'hash' => $inspection['hash'] ?? null,
                'metadata_source' => $inspection['metadata_source'] ?? 'geode_archive',
                'metadata_warning' => $inspection['metadata_warning'] ?? null,
                'geode' => isset($inner['geode']) ? normalize_geode($inner['geode']) : (isset($body['geode']) ? normalize_geode($body['geode']) : null),
                'download_count' => 0,
                'early_load' => bool_value($body['early_load'] ?? false),
                'requires_patching' => bool_value($body['requires_patching'] ?? false),
                'api' => bool_value($inner['api'] ?? ($body['api'] ?? false)),
                'mod_id' => $id,
                'gd' => isset($inner['gd']) ? normalize_gd($inner['gd']) : (isset($body['gd']) ? normalize_gd($body['gd']) : null),
                'status' => 'accepted',
                'description' => isset($inner['description']) && is_scalar($inner['description']) ? clean_utf8((string)$inner['description']) : (isset($body['description']) ? clean_utf8((string)$body['description']) : (!empty($new_metadata['about']) ? text_width($new_metadata['about'], 1000, '...') : null)),
                'created_at' => $now,
                'updated_at' => $now,
            ];

            if (!isset($mods[$i]['versions']) || !is_array($mods[$i]['versions'])) $mods[$i]['versions'] = [];
            $replaced = false;
            foreach ($mods[$i]['versions'] as $version_index => $old_version) {
                if (($old_version['version'] ?? null) === $version) {
                    $new_version['download_count'] = (int)($old_version['download_count'] ?? 0);
                    $new_version['created_at'] = $old_version['created_at'] ?? $now;
                    $mods[$i]['versions'][$version_index] = $new_version;
                    $replaced = true;
                    break;
                }
            }
            if (!$replaced) array_unshift($mods[$i]['versions'], $new_version);
            api_log('mod.update.owner', ['id' => $id, 'version' => $version, 'replaced' => $replaced]);
        }

        if ($new_metadata !== null) {
            if (!empty($new_metadata['about'])) $mods[$i]['about'] = $new_metadata['about'];
            if (!empty($new_metadata['changelog'])) $mods[$i]['changelog'] = $new_metadata['changelog'];
        } elseif (bool_value($body['refresh_metadata'] ?? false) && !empty($mods[$i]['versions'][0]['download_link'])) {
            $refresh = extract_metadata_from_geode($mods[$i]['versions'][0]['download_link']);
            if (is_array($refresh)) {
                if (!empty($refresh['about'])) $mods[$i]['about'] = $refresh['about'];
                if (!empty($refresh['changelog'])) $mods[$i]['changelog'] = $refresh['changelog'];
            }
        }

        $mods[$i]['updated_at'] = iso8601_utc();
        if (!db_write('mods.json', $mods)) return json_response(['error' => 'Could not save mod changes', 'payload' => null], 500);
        return json_response(['error' => '', 'payload' => mod_for_public($mods[$i])], 200);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mods_delete($id) {
    if (!require_auth()) return;
    $u = current_user();

    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    foreach ($mods as $i => $m) {
        if (!is_array($m) || ($m['id'] ?? null) !== $id) continue;
        if (!mod_user_can_manage($m, $u)) return json_response(['error' => 'forbidden - only owner or admin can delete', 'payload' => null], 403);

        array_splice($mods, $i, 1);
        if (!db_write('mods.json', $mods)) return json_response(['error' => 'Could not delete mod', 'payload' => null], 500);

        $deprec = db_read('deprecations.json');
        if (!is_array($deprec)) $deprec = [];
        $deprec = array_values(array_filter($deprec, fn($d) => !is_array($d) || !isset($d['mod_id']) || $d['mod_id'] !== $id));
        db_write('deprecations.json', $deprec);

        api_log('mod.delete', ['id' => $id]);
        return json_response(['error' => '', 'payload' => null], 204);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mods_updates() {
    $q = $_GET;
    if (!isset($q['ids']) || !is_scalar($q['ids']) || trim((string)$q['ids']) === '') return json_response(['error' => 'bad request - ids required', 'payload' => null], 400);

    // [PATCH] cap input size
    $raw = trim((string)$q['ids']);
    if (strlen($raw) > 20000) return json_response(['error' => 'ids too long', 'payload' => null], 400);

    $up = fetch_upstream_json('/v1/mods/updates', $q);
    $up_payload = ['deprecations' => [], 'updates' => []];
    if ($up && isset($up['error']) && $up['error'] === '' && isset($up['payload']) && is_array($up['payload'])) {
        $up_payload = $up['payload'];
        if (!is_array($up_payload['deprecations'] ?? null)) $up_payload['deprecations'] = [];
        if (!is_array($up_payload['updates'] ?? null)) $up_payload['updates'] = [];
    }

    $ids = array_values(array_unique(array_filter(array_map('trim', preg_split('/[;,]+/', $raw)), function ($id) { return $id !== ''; })));
    if (count($ids) > 500) return json_response(['error' => 'Too many mod IDs (maximum 500)', 'payload' => null], 400);
    $client_geode = isset($q['geode']) && is_scalar($q['geode']) ? (string)$q['geode'] : null;
    $client_gd = isset($q['gd']) && is_scalar($q['gd']) ? (string)$q['gd'] : null;
    $platform = isset($q['platform']) && is_scalar($q['platform']) ? (string)$q['platform'] : (isset($q['platforms']) && is_scalar($q['platforms']) ? (string)$q['platforms'] : null);

    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    $deprec = db_read('deprecations.json');
    if (!is_array($deprec)) $deprec = [];

    $mods_index = [];
    foreach ($mods as $m) if (is_array($m) && !empty($m['id'])) $mods_index[(string)$m['id']] = $m;

    $local_deprec = array_values(array_filter($deprec, fn($d) => is_array($d) && isset($d['mod_id']) && in_array($d['mod_id'], $ids, true)));

    $local_updates = [];
    foreach ($ids as $id) {
        if (!isset($mods_index[$id])) continue;
        $mod = $mods_index[$id];
        $chosen = null;

        if (!empty($mod['versions']) && is_array($mod['versions'])) {
            foreach ($mod['versions'] as $v) {
                if (!is_array($v)) continue;
                if (!empty($v['status']) && strtolower((string)$v['status']) !== 'accepted') continue;
                $v_geode = isset($v['geode']) ? normalize_geode($v['geode']) : null;
                if ($v_geode !== null && $client_geode !== null && version_compare($v_geode, $client_geode, '>')) continue;

                $v_gd = $v['gd'] ?? ($mod['gd'] ?? null);
                if (!empty($client_gd) && !gd_target_is_compatible($v_gd, $client_gd, $platform)) continue;
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

    if (!empty($client_gd)) {
        $up_payload['updates'] = array_values(array_filter($up_payload['updates'], function ($u) use ($client_gd, $platform) {
            return is_array($u) && gd_target_is_compatible($u['gd'] ?? null, $client_gd, $platform);
        }));
    }

    $upstream_updates = array_values(array_filter($up_payload['updates'], fn($u) => is_array($u) && !empty($u['id'])));
    $merged_updates = [];
    foreach ($upstream_updates as $u) $merged_updates[(string)$u['id']] = $u;
    foreach ($local_updates as $lu) $merged_updates[(string)$lu['id']] = $lu;

    $final_updates = [];
    foreach ($upstream_updates as $u) {
        $key = (string)$u['id'];
        if (isset($merged_updates[$key])) { $final_updates[] = $merged_updates[$key]; unset($merged_updates[$key]); }
    }
    foreach ($merged_updates as $rem) $final_updates[] = $rem;

    $upstream_deprecations = array_values(array_filter($up_payload['deprecations'], 'is_array'));
    $all_deprec = array_merge($upstream_deprecations, $local_deprec);
    $seen = [];
    $final_deprec = [];
    foreach ($all_deprec as $d) {
        $key = ($d['mod_id'] ?? '') . '|' . ($d['id'] ?? md5(json_encode_safe($d, false)));
        if (isset($seen[$key])) continue;
        $seen[$key] = true;
        $final_deprec[] = $d;
    }

    json_response(['error' => '', 'payload' => ['deprecations' => $final_deprec, 'updates' => array_values($final_updates)]], 200);
}

/* ======================= API: deprecations ======================= */

function api_deprecations_index($modid) {
    $deprec = db_read('deprecations.json');
    if (!is_array($deprec)) $deprec = [];
    $out = array_values(array_filter($deprec, fn($d) => is_array($d) && isset($d['mod_id']) && $d['mod_id'] === $modid));
    json_response(['error' => '', 'payload' => $out]);
}

function api_deprecations_create($modid) {
    if (!require_auth()) return;
    $body = json_input();
    if (!is_array($body) || !isset($body['reason']) || !is_scalar($body['reason'])) return json_response(['error' => request_input_error('reason is required'), 'payload' => null], 400);

    $reason = trim((string)$body['reason']);
    if ($reason === '' || strlen($reason) > 10000) return json_response(['error' => 'reason must be between 1 and 10000 bytes', 'payload' => null], 400);
    $deprecations = db_read('deprecations.json');
    if (!is_array($deprecations)) $deprecations = [];
    $row = [
        'id' => next_numeric_id($deprecations),
        'mod_id' => $modid,
        'by' => current_user(),
        'reason' => clean_utf8($reason),
        'created_at' => iso8601_utc(),
    ];
    $deprecations[] = $row;
    if (!db_write('deprecations.json', $deprecations)) return json_response(['error' => 'Could not save deprecation', 'payload' => null], 500);
    json_response(['error' => '', 'payload' => $row], 201);
}

function api_deprecations_clear_all($modid) {
    if (!require_admin()) return;
    $deprec = db_read('deprecations.json');
    if (!is_array($deprec)) $deprec = [];
    $deprec = array_values(array_filter($deprec, fn($d) => !is_array($d) || !isset($d['mod_id']) || $d['mod_id'] !== $modid));
    if (!db_write('deprecations.json', $deprec)) return json_response(['error' => 'Could not clear deprecations', 'payload' => null], 500);
    json_response(['error' => '', 'payload' => null], 204);
}

function api_deprecations_update($modid, $depid) {
    if (!require_admin()) return;
    $body = json_input();
    if (!is_array($body) || !$body) return json_response(['error' => request_input_error('bad request'), 'payload' => null], 400);

    $deprec = db_read('deprecations.json') ?: [];
    foreach ($deprec as $i => $d) {
        if (is_array($d) && (int)($d['id'] ?? 0) === $depid && ($d['mod_id'] ?? null) === $modid) {
            if (isset($body['by'])) {
                if (!is_scalar($body['by'])) return json_response(['error' => 'by must be text', 'payload' => null], 400);
                $deprec[$i]['by'] = clean_utf8((string)$body['by']);
            }
            if (isset($body['reason'])) {
                if (!is_scalar($body['reason']) || trim((string)$body['reason']) === '' || strlen((string)$body['reason']) > 10000) return json_response(['error' => 'reason must be text between 1 and 10000 bytes', 'payload' => null], 400);
                $deprec[$i]['reason'] = clean_utf8((string)$body['reason']);
            }
            if (!db_write('deprecations.json', $deprec)) return json_response(['error' => 'Could not save deprecation', 'payload' => null], 500);
            return json_response(['error' => '', 'payload' => $deprec[$i]], 200);
        }
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

function api_deprecations_delete($modid, $depid) {
    if (!require_admin()) return;
    $deprec = db_read('deprecations.json');
    if (!is_array($deprec)) $deprec = [];
    foreach ($deprec as $i => $d) {
        if (is_array($d) && (int)($d['id'] ?? 0) === $depid && ($d['mod_id'] ?? null) === $modid) {
            array_splice($deprec, $i, 1);
            if (!db_write('deprecations.json', $deprec)) return json_response(['error' => 'Could not delete deprecation', 'payload' => null], 500);
            return json_response(['error' => '', 'payload' => null], 204);
        }
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

/* ======================= API: mod developers ======================= */

function api_mod_add_developer($modid) {
    if (!require_auth()) return;
    $body = json_input();
    if (!is_array($body) || !isset($body['username']) || !is_scalar($body['username']) || trim((string)$body['username']) === '') return json_response(['error' => request_input_error('username is required'), 'payload' => null], 400);

    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if (!is_array($m) || ($m['id'] ?? null) !== $modid) continue;

        $u = current_user();
        if (!mod_user_can_manage($m, $u)) return json_response(['error' => 'forbidden', 'payload' => null], 403);
        if (!isset($mods[$i]['developers']) || !is_array($mods[$i]['developers'])) $mods[$i]['developers'] = [];

        $username = trim((string)$body['username']);
        if (!preg_match('/^(?!-)[A-Za-z0-9-]{1,39}(?<!-)$/', $username)) return json_response(['error' => 'Invalid GitHub username', 'payload' => null], 400);
        if (isset($body['role']) && !is_scalar($body['role'])) return json_response(['error' => 'Invalid developer role', 'payload' => null], 400);
        $role = !empty($body['role']) ? trim((string)$body['role']) : null;
        $allowed_roles = ['Owner', 'Developer', 'Porter', 'Contributor'];
        if ($role !== null && !in_array($role, $allowed_roles, true)) return json_response(['error' => 'Invalid developer role', 'payload' => null], 400);
        $is_owner = array_key_exists('is_owner', $body) ? bool_value($body['is_owner']) : (strtolower((string)$role) === 'owner');
        if ($role === null) $role = default_developer_role($is_owner);

        $found = false;
        foreach ($mods[$i]['developers'] as $j => $d) {
            if (is_array($d) && !empty($d['username']) && $d['username'] === $username) {
                $mods[$i]['developers'][$j]['is_owner'] = $is_owner;
                $mods[$i]['developers'][$j]['role'] = $role;
                $found = true;
                break;
            }
        }
        if (!$found) $mods[$i]['developers'][] = ['id' => null, 'username' => $username, 'display_name' => $username, 'is_owner' => $is_owner, 'role' => $role];

        $mods[$i]['updated_at'] = iso8601_utc();
        if (!db_write('mods.json', $mods)) return json_response(['error' => 'Could not save developer changes', 'payload' => null], 500);
        return json_response(['error' => '', 'payload' => null], 204);
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

function api_mod_remove_developer($modid, $username) {
    if (!require_auth()) return;
    $mods = db_read('mods.json') ?: [];
    foreach ($mods as $i => $m) {
        if (!is_array($m) || ($m['id'] ?? null) !== $modid) continue;

        $u = current_user();
        if (!mod_user_can_manage($m, $u)) return json_response(['error' => 'forbidden', 'payload' => null], 403);
        if (!isset($mods[$i]['developers']) || !is_array($mods[$i]['developers'])) $mods[$i]['developers'] = [];

        $target_index = null;
        $remaining_owners = 0;
        foreach ($mods[$i]['developers'] as $j => $developer) {
            if (!is_array($developer)) continue;
            if (!empty($developer['is_owner']) && strcasecmp((string)($developer['username'] ?? ''), (string)$username) !== 0) $remaining_owners++;
            if (strcasecmp((string)($developer['username'] ?? ''), (string)$username) === 0) $target_index = $j;
        }
        if ($target_index !== null) {
            if (!empty($mods[$i]['developers'][$target_index]['is_owner']) && $remaining_owners === 0 && !is_admin()) return json_response(['error' => 'Cannot remove the last owner; assign another owner first', 'payload' => null], 409);
            array_splice($mods[$i]['developers'], $target_index, 1);
            $mods[$i]['updated_at'] = iso8601_utc();
            if (!db_write('mods.json', $mods)) return json_response(['error' => 'Could not remove developer', 'payload' => null], 500);
            return json_response(['error' => '', 'payload' => null], 204);
        }
        return json_response(['error' => 'developer not found', 'payload' => null], 404);
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

function api_mod_logo($modid) {
    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    foreach ($mods as $m) {
        if (!is_array($m) || ($m['id'] ?? null) !== $modid) continue;
        if (!empty($m['logo_url']) && is_string($m['logo_url']) && is_safe_url($m['logo_url'])) { header('Location: ' . $m['logo_url'], true, 302); exit; }
        $repo = normalize_github_repo($m['repo'] ?? null);
        if ($repo !== null) { header('Location: https://raw.githubusercontent.com/' . $repo . '/HEAD/logo.png', true, 302); exit; }
        json_response(['error' => 'not found', 'payload' => null], 404);
    }

    if (defined('UPSTREAM_URL') && is_string(UPSTREAM_URL) && is_safe_url(rtrim(UPSTREAM_URL, '/'))) {
        $url = rtrim(UPSTREAM_URL, '/') . '/v1/mods/' . rawurlencode($modid) . '/logo';
        header('Location: ' . $url, true, 302);
        exit;
    }
    json_response(['error' => 'not found', 'payload' => null], 404);
}

/* ======================= API: versions ======================= */

function api_mod_versions_index($modid) {
    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    foreach ($mods as $mod) {
        if (!is_array($mod) || ($mod['id'] ?? null) !== $modid) continue;
        $client_gd = isset($_GET['gd']) && is_scalar($_GET['gd']) && $_GET['gd'] !== '' ? (string)$_GET['gd'] : null;
        $client_platform = isset($_GET['platform']) && is_scalar($_GET['platform']) ? (string)$_GET['platform'] : (isset($_GET['platforms']) && is_scalar($_GET['platforms']) ? (string)$_GET['platforms'] : null);
        $filtered = filter_mod_for_client_gd($mod, $client_gd, $client_platform);
        if ($filtered === null) return json_response(['error' => 'mod not found for this GD version', 'payload' => null], 404);
        $out = [];
        $versions = is_array($filtered['versions'] ?? null) ? $filtered['versions'] : [];
        foreach ($versions as $version_entry) if (is_array($version_entry)) $out[] = version_for_public($modid, $version_entry);
        return json_response(['error' => '', 'payload' => $out]);
    }

    if (defined('UPSTREAM_URL') && UPSTREAM_URL) {
        $up = fetch_upstream_json('/v1/mods/' . rawurlencode($modid) . '/versions');
        if (is_array($up) && ($up['error'] ?? null) === '' && is_array($up['payload'] ?? null)) {
            $client_gd = isset($_GET['gd']) && is_scalar($_GET['gd']) && $_GET['gd'] !== '' ? (string)$_GET['gd'] : null;
            $client_platform = isset($_GET['platform']) && is_scalar($_GET['platform']) ? (string)$_GET['platform'] : (isset($_GET['platforms']) && is_scalar($_GET['platforms']) ? (string)$_GET['platforms'] : null);
            $payload = array_values(array_filter($up['payload'], function ($version_entry) use ($client_gd, $client_platform) {
                return is_array($version_entry) && ($client_gd === null || gd_target_is_compatible($version_entry['gd'] ?? null, $client_gd, $client_platform));
            }));
            return json_response(['error' => '', 'payload' => $payload]);
        }
        if ($up === null) return json_response(['error' => 'upstream unavailable', 'payload' => null], 502);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mod_versions_create($modid) {
    if (!require_auth()) return;
    $body = json_input();
    if (!is_array($body) || !isset($body['download_link']) || !is_scalar($body['download_link']) || trim((string)$body['download_link']) === '') return json_response(['error' => request_input_error('download_link is required and must be text'), 'payload' => null], 400);

    $download_link = trim((string)$body['download_link']);
    if (!is_safe_url($download_link)) return json_response(['error' => 'download_link must be a public HTTP(S) URL', 'payload' => null], 400);

    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    foreach ($mods as $i => $mod) {
        if (!is_array($mod) || ($mod['id'] ?? null) !== $modid) continue;
        if (!mod_user_can_manage($mod)) return json_response(['error' => 'forbidden - only owner or admin can publish versions', 'payload' => null], 403);

        $inspection = inspect_remote_geode_with_repo_fallback($download_link, $mod['repo'] ?? null);
        if (!empty($inspection['error'])) {
            $status = strpos($inspection['error'], 'ZipArchive') !== false ? 503 : 400;
            return json_response(['error' => $inspection['error'], 'payload' => null], $status);
        }
        $metadata = $inspection['metadata'];
        $inner = $metadata['modjson'];
        if (!empty($inner['id']) && (string)$inner['id'] !== (string)$modid) {
            return json_response(['error' => 'mod id inside .geode does not match the target mod id', 'payload' => null], 400);
        }

        $version = normalize_version($body['version'] ?? ($inner['version'] ?? null)) ?: date('YmdHis');
        if (!valid_version_string($version)) return json_response(['error' => 'Invalid version string', 'payload' => null], 400);
        $now = iso8601_utc();
        $new_version = [
            'name' => isset($inner['name']) && is_scalar($inner['name']) ? clean_utf8((string)$inner['name']) : (isset($body['name']) && is_scalar($body['name']) ? clean_utf8((string)$body['name']) : $modid),
            'version' => $version,
            'download_link' => $download_link,
            'hash' => $inspection['hash'] ?? null,
            'metadata_source' => $inspection['metadata_source'] ?? 'geode_archive',
            'metadata_warning' => $inspection['metadata_warning'] ?? null,
            'geode' => isset($inner['geode']) ? normalize_geode($inner['geode']) : (isset($body['geode']) ? normalize_geode($body['geode']) : null),
            'download_count' => 0,
            'early_load' => bool_value($body['early_load'] ?? false),
            'requires_patching' => bool_value($body['requires_patching'] ?? false),
            'api' => bool_value($inner['api'] ?? ($body['api'] ?? false)),
            'mod_id' => $modid,
            'gd' => isset($inner['gd']) ? normalize_gd($inner['gd']) : (isset($body['gd']) ? normalize_gd($body['gd']) : null),
            'status' => 'accepted',
            'description' => isset($inner['description']) && is_scalar($inner['description']) ? clean_utf8((string)$inner['description']) : (!empty($metadata['about']) ? text_width($metadata['about'], 1000, '...') : null),
            'created_at' => $now,
            'updated_at' => $now,
        ];

        if (!isset($mods[$i]['versions']) || !is_array($mods[$i]['versions'])) $mods[$i]['versions'] = [];
        $replaced = false;
        foreach ($mods[$i]['versions'] as $version_index => $old_version) {
            if (!is_array($old_version)) continue;
            if (($old_version['version'] ?? null) === $version) {
                $new_version['download_count'] = (int)($old_version['download_count'] ?? 0);
                $new_version['created_at'] = $old_version['created_at'] ?? $now;
                $mods[$i]['versions'][$version_index] = $new_version;
                $replaced = true;
                break;
            }
        }
        if (!$replaced) array_unshift($mods[$i]['versions'], $new_version);
        if (!empty($metadata['about'])) $mods[$i]['about'] = $metadata['about'];
        if (!empty($metadata['changelog'])) $mods[$i]['changelog'] = $metadata['changelog'];
        $mods[$i]['updated_at'] = $now;

        if (!db_write('mods.json', $mods)) return json_response(['error' => 'Could not save the new version', 'payload' => null], 500);
        api_log('mod.version.create', ['id' => $modid, 'version' => $version, 'replaced' => $replaced]);
        json_response(['error' => '', 'payload' => version_for_public($modid, $new_version)], $replaced ? 200 : 201);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mod_versions_get($modid, $version) {
    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    foreach ($mods as $mod) {
        if (!is_array($mod) || ($mod['id'] ?? null) !== $modid) continue;
        $client_gd = isset($_GET['gd']) && is_scalar($_GET['gd']) && $_GET['gd'] !== '' ? (string)$_GET['gd'] : null;
        $client_platform = isset($_GET['platform']) && is_scalar($_GET['platform']) ? (string)$_GET['platform'] : (isset($_GET['platforms']) && is_scalar($_GET['platforms']) ? (string)$_GET['platforms'] : null);
        $filtered = filter_mod_for_client_gd($mod, $client_gd, $client_platform);
        if ($filtered === null) return json_response(['error' => 'mod not found for this GD version', 'payload' => null], 404);
        foreach ((is_array($filtered['versions'] ?? null) ? $filtered['versions'] : []) as $entry) {
            if (is_array($entry) && ($entry['version'] ?? null) === $version) return json_response(['error' => '', 'payload' => version_for_public($modid, $entry)]);
        }
        return json_response(['error' => 'version not found for this GD version', 'payload' => null], 404);
    }

    if (defined('UPSTREAM_URL') && UPSTREAM_URL) {
        $up = fetch_upstream_json('/v1/mods/' . rawurlencode($modid) . '/versions/' . rawurlencode($version));
        if (is_array($up) && ($up['error'] ?? null) === '' && is_array($up['payload'] ?? null)) {
            $client_gd = isset($_GET['gd']) && is_scalar($_GET['gd']) && $_GET['gd'] !== '' ? (string)$_GET['gd'] : null;
            $client_platform = isset($_GET['platform']) && is_scalar($_GET['platform']) ? (string)$_GET['platform'] : (isset($_GET['platforms']) && is_scalar($_GET['platforms']) ? (string)$_GET['platforms'] : null);
            if ($client_gd !== null && !gd_target_is_compatible($up['payload']['gd'] ?? null, $client_gd, $client_platform)) {
                return json_response(['error' => 'version not found for this GD version', 'payload' => null], 404);
            }
            return json_response(['error' => '', 'payload' => $up['payload']]);
        }
        if ($up === null) return json_response(['error' => 'upstream unavailable', 'payload' => null], 502);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mod_versions_update($modid, $version) {
    if (!require_admin()) return;
    $body = json_input();
    if (!is_array($body) || !$body) return json_response(['error' => request_input_error('bad request'), 'payload' => null], 400);

    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    foreach ($mods as $i => $mod) {
        if (!is_array($mod) || ($mod['id'] ?? null) !== $modid) continue;
        foreach ((is_array($mod['versions'] ?? null) ? $mod['versions'] : []) as $j => $entry) {
            if (!is_array($entry) || ($entry['version'] ?? null) !== $version) continue;

            if (isset($body['status'])) {
                if (!is_scalar($body['status'])) return json_response(['error' => 'Invalid version status', 'payload' => null], 400);
                $status = strtolower(trim((string)$body['status']));
                if (!in_array($status, ['accepted', 'rejected', 'pending', 'deprecated'], true)) return json_response(['error' => 'Invalid version status', 'payload' => null], 400);
                $mods[$i]['versions'][$j]['status'] = $status;
            }
            if (isset($body['info'])) {
                if (!is_scalar($body['info'])) return json_response(['error' => 'info must be text', 'payload' => null], 400);
                $mods[$i]['versions'][$j]['info'] = clean_utf8((string)$body['info']);
            }
            if (isset($body['download_link']) && !is_scalar($body['download_link'])) return json_response(['error' => 'download_link must be text', 'payload' => null], 400);
            if (!empty($body['download_link'])) {
                $download_link = trim((string)$body['download_link']);
                if (!is_safe_url($download_link)) return json_response(['error' => 'download_link must be a public HTTP(S) URL', 'payload' => null], 400);
                $hash = compute_remote_sha256($download_link);
                if ($hash === null) return json_response(['error' => 'Could not download file or calculate SHA-256; version was not changed', 'payload' => null], 400);
                $mods[$i]['versions'][$j]['download_link'] = $download_link;
                $mods[$i]['versions'][$j]['hash'] = $hash;
            }

            $mods[$i]['versions'][$j]['updated_at'] = iso8601_utc();
            $mods[$i]['updated_at'] = iso8601_utc();
            if (!db_write('mods.json', $mods)) return json_response(['error' => 'Could not save version changes', 'payload' => null], 500);
            return json_response(['error' => '', 'payload' => $mods[$i]['versions'][$j]], 200);
        }
        return json_response(['error' => 'version not found', 'payload' => null], 404);
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

function api_mod_versions_download($modid, $version) {
    $mods = db_read('mods.json');
    if (!is_array($mods)) $mods = [];
    foreach ($mods as $i => $mod) {
        if (!is_array($mod) || ($mod['id'] ?? null) !== $modid) continue;
        foreach ((is_array($mod['versions'] ?? null) ? $mod['versions'] : []) as $j => $entry) {
            if (!is_array($entry) || ($entry['version'] ?? null) !== $version) continue;
            $download_link = trim((string)($entry['download_link'] ?? ''));
            if ($download_link !== '' && is_safe_url($download_link)) {
                $resolved = resolve_final_url($download_link);
                $target = !empty($resolved['url']) ? $resolved['url'] : $download_link;
                if (!empty($resolved['url']) && $resolved['code'] >= 200 && $resolved['code'] < 400) {
                    $mods[$i]['versions'][$j]['download_count'] = (int)($mods[$i]['versions'][$j]['download_count'] ?? 0) + 1;
                    $mods[$i]['download_count'] = (int)($mods[$i]['download_count'] ?? 0) + 1;
                    db_write('mods.json', $mods);
                }
                header('Location: ' . $target, true, 302);
                exit;
            }
            return json_response(['error' => 'version download link is missing or unsafe', 'payload' => null], 502);
        }
        return json_response(['error' => 'version not found', 'payload' => null], 404);
    }

    if (defined('UPSTREAM_URL') && UPSTREAM_URL && is_safe_url(rtrim((string)UPSTREAM_URL, '/'))) {
        $url = rtrim((string)UPSTREAM_URL, '/') . '/v1/mods/' . rawurlencode($modid) . '/versions/' . rawurlencode($version) . '/download';
        header('Location: ' . $url, true, 302);
        exit;
    }
    json_response(['error' => 'mod not found', 'payload' => null], 404);
}

/* ======================= API: stats ======================= */

function api_stats() {
    // stats changes often (counters), but a 30s etag is still useful
    json_response_etag(['error' => '', 'payload' => api_stats_payload()], 200, 30);
}

/* ======================= UI renderers ======================= */

function handle_home() { header('Location: /ui'); exit; }

// [PATCH] now sends X-CSRF-Token and doesn't try to reload on error unless needed.
function asAPIReqForm($selector = 'form') {
    $selector_json = json_encode($selector, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $csrf_json = json_encode(CSRF_TOKEN);
    return <<<HTML
<script>
(function(){
'use strict';
const selector = $selector_json;
const csrf = $csrf_json;
const form = document.querySelector(selector);
if (!form) return;
form.addEventListener('submit', async function(event) {
    event.preventDefault();
    const button = form.querySelector('button[type="submit"]') || form.querySelector('button');
    const originalDisabled = button ? button.disabled : false;
    if (button) button.disabled = true;
    const status = form.querySelector('[role="status"]');
    if (status) status.textContent = 'Reading mod metadata and calculating the package checksum…';
    try {
        const response = await fetch(form.action, {
            method: (form.method || 'POST').toUpperCase(),
            body: new FormData(form),
            headers: { 'X-CSRF-Token': csrf, 'Accept': 'application/json' }
        });
        const raw = await response.text();
        let data = null;
        if (raw.trim() !== '') {
            try {
                data = JSON.parse(raw);
            } catch (_) {
                const preview = raw.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 240);
                throw new Error('Server returned non-JSON response (HTTP ' + response.status + ')' + (preview ? ': ' + preview : '. Check PHP error log.'));
            }
        }
        if (!response.ok) throw new Error((data && data.error) || ('HTTP ' + response.status));
        if (data && data.error) throw new Error(data.error);
        const fromRepository = data && data.payload && data.payload.metadata_source === 'github_repository';
        if (status) status.textContent = fromRepository ? 'Published using GitHub release metadata and its SHA-256 digest.' : 'Published successfully. The .geode archive was inspected.';
        alert(fromRepository ? 'Published successfully. Mod information and SHA-256 were recovered from GitHub release metadata.' : 'Published successfully. The .geode archive was inspected and its SHA-256 was calculated.');
        window.location.reload();
    } catch (error) {
        alert('Error: ' + (error && error.message ? error.message : 'Request failed'));
        if (status) status.textContent = error && error.message ? error.message : 'Request failed';
        if (button) button.disabled = originalDisabled;
    }
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
<script>
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => { new bootstrap.Tooltip(el); });
    document.querySelectorAll('[data-bs-toggle="popover"]').forEach(el => { new bootstrap.Popover(el); });
    document.querySelectorAll('[data-bs-spy="scroll"]').forEach(el => { new bootstrap.ScrollSpy(el); });
    document.querySelectorAll('.toast').forEach(el => { new bootstrap.Toast(el); });
});
</script>
</body>
</html>
    <?php
}

/* ======================= OAuth result pages ======================= */

function render_oauth_error($title, $description, array $details = []) {
    http_response_code(400);

    $e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    $title_e = $e($title);
    $desc_e  = $e($description);

    // Targeted hints per GitHub error code
    $hint_map = [
        'redirect_uri_mismatch'        => 'The Callback URL in your GitHub OAuth App does not match the one the site sends. Compare them byte-for-byte: scheme (http/https), domain, port and path.',
        'bad_verification_code'        => 'The authorization code was already used or has expired. Start the login flow again — do not reload /callback.',
        'incorrect_client_credentials' => 'CLIENT_ID or CLIENT_SECRET in _config.php is wrong.',
        'application_suspended'        => 'The OAuth App has been suspended on GitHub.',
        'network'                      => 'The server could not reach github.com. Check allow_url_fopen, DNS and SSL certificates.',
    ];
    $gerr = $details['github_error'] ?? '';
    $hint = $gerr && isset($hint_map[$gerr]) ? $hint_map[$gerr] : '';

    ui_header('OAuth error · Open Geode Index', 'Authorization failed');
    ?>
    <div class="row justify-content-center">
      <div class="col-lg-8">
        <div class="alert alert-danger d-flex align-items-start gap-2">
          <i class="bi bi-exclamation-triangle-fill fs-4"></i>
          <div>
            <h3 class="alert-heading mb-1"><?=$title_e?></h3>
            <div><?=$desc_e?></div>
          </div>
        </div>

        <?php if ($hint): ?>
          <div class="alert alert-warning">
            <strong>What to do:</strong> <?=$e($hint)?>
          </div>
        <?php endif; ?>

        <div class="card mb-3">
          <div class="card-header">Technical details</div>
          <div class="card-body">
            <table class="table table-sm table-borderless mb-0">
              <tbody>
                <?php foreach ($details as $k => $v): ?>
                  <?php if ($v === null) continue; ?>
                  <tr>
                    <th class="text-secondary" style="width:180px;"><?=$e($k)?></th>
                    <td><code style="white-space:pre-wrap;word-break:break-all;"><?=$e(is_array($v) ? json_encode($v, JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT) : (string)$v)?></code></td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
        </div>

        <div class="d-flex gap-2">
          <a href="/login" class="btn btn-primary"><i class="bi bi-github"></i> Try signing in again</a>
          <a href="/ui" class="btn btn-dark">Back to home</a>
          <button class="btn btn-dark" onclick="navigator.clipboard && navigator.clipboard.writeText(document.querySelector('.card-body code')?.innerText || '').then(()=>this.innerText='Copied!')">Copy details</button>
        </div>
      </div>
    </div>
    <?php
    ui_footer();
    exit;
}

function render_oauth_success($username, array $tokens) {
    $e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    ui_header('Login successful · Open Geode Index', 'You are signed in');
    ?>
    <div class="row justify-content-center">
      <div class="col-lg-7">
        <div class="alert alert-success d-flex align-items-center gap-2">
          <i class="bi bi-check-circle-fill fs-4"></i>
          <div><strong>Signed in as <a href="https://github.com/<?=$e($username)?>" target="_blank"><?=$e($username)?></a></strong></div>
        </div>

        <div class="card mb-3">
          <div class="card-header">Access tokens (save these if you use the API)</div>
          <div class="card-body">
            <label class="form-label small text-secondary mb-1">Access token</label>
            <div class="input-group mb-2">
              <input class="form-control" readonly value="<?=$e($tokens['access_token'])?>">
            </div>
            <label class="form-label small text-secondary mb-1">Refresh token</label>
            <div class="input-group mb-2">
              <input class="form-control" readonly value="<?=$e($tokens['refresh_token'])?>">
            </div>
            <div class="form-text">Access token lives 7 days, refresh token 30 days. They are already bound to your session in this browser.</div>
          </div>
        </div>

        <div class="d-flex gap-2">
          <a href="/ui" class="btn btn-primary">Go to catalog</a>
          <a href="/v1/me" class="btn btn-dark">Check /v1/me</a>
        </div>
      </div>
    </div>
    <?php
    ui_footer();
    exit;
}

function render_ui() {
    $stats = api_stats_payload();
    $user = current_user();
    $publish_flash = $_SESSION['ogi_publish_flash'] ?? null;
    unset($_SESSION['ogi_publish_flash']);
    ui_header('Open Geode Index');
    ?>
    <style>
        .highlight-search { background: yellow !important; color: black !important; }
        .skeleton-card { height: 92px; border-radius: 8px; animation: pulse 1.5s ease-in-out infinite; background: var(--bs-secondary-bg); }
        @keyframes pulse { 0%, 100% { opacity: 0.4; } 50% { opacity: 0.8; } }
        .tag-btn { font-size: 0.7rem; padding: 2px 10px; border-radius: 12px; border: 1px solid var(--bs-border-color); background: transparent; color: var(--bs-secondary-color); cursor: pointer; transition: all 0.15s; text-transform: capitalize; }
        .tag-btn:hover { background: var(--bs-secondary-bg); }
        .tag-btn.active { background: var(--bs-primary); color: #fff; border-color: var(--bs-primary); }
        .filter-section { background: rgba(255,255,255,0.03); border-radius: 8px; padding: 12px 16px; }
        .empty-state { text-align: center; padding: 40px 20px; color: var(--bs-secondary-color); }
        .pagination-bar { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
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
            <p style="display: flex;justify-content: space-between;">
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
            <?php if (is_array($publish_flash) && !empty($publish_flash['message'])): ?>
                <?php $flash_type = in_array(($publish_flash['type'] ?? ''), ['success', 'warning', 'danger'], true) ? $publish_flash['type'] : 'info'; ?>
                <div class="alert alert-<?=$flash_type?> py-2" role="alert"><?=htmlspecialchars((string)$publish_flash['message'], ENT_QUOTES, 'UTF-8')?></div>
            <?php endif; ?>
            <?php if (!$user): ?>
                <div class="alert alert-warning">Please <a href="/login">sign in with GitHub</a> to submit mods.</div>
            <?php else: ?>
                <p class="text-muted" style="
                    line-height: 16px;
                    font-size-adjust: ch-width 0.5;
                ">
                    You can post <a data-bs-toggle="tooltip" data-bs-placement="top" title="" style="cursor: help;" data-original-title="Even reuploads, unauthorised ports and updates, Side-B mod versions, AI slop, cheats, exploits and experiments" class="btn-link theme-primary">anything</a> you want but malware, pls provide us valid GitHub Repository cuz logo loading form it (user/repo/HEAD/logo.png)<br><br>You also can upload not your mods, but it would be sweet if you go to mod page and change developer displayname on real one instead you.<br><br>If you are developer and ownership of your repository was taken pls <a target="_blank" href="https://github.com/lil2kki/Open-Geode-Index/issues/new">send report here</a> so i give you access.
                </p>
                <form method="post" id="post-mod-form" action="/v1/mods" class="h-100" style="
                    display: flex;
                    flex-direction: column;
                    justify-content: flex-end;
                ">
                    <input type="hidden" name="csrf" value="<?=htmlspecialchars(CSRF_TOKEN, ENT_QUOTES)?>">
                    <div class="form-group">
                        <label for="repo" data-bs-toggle="tooltip" data-bs-placement="top" title="" style="cursor: help;" 
                            data-original-title="If the server cannot inspect the .geode archive, the index can read mod.json, README/about and changelog from this repository. A valid SHA-256 is still required for Geode downloads."
                        >Repository (user/repo)</label>
                        <input id="repo" name="repo" class="form-control" placeholder="lil2kki/mod" required>
                    </div>
                    <div class="form-group my-2">
                        <label for="download_link">Download link (.geode)</label>
                        <input id="download_link" name="download_link" class="form-control" type="url" placeholder="https://github.com/.../releases/download/vX.Y/file.geode" required>
                        <div class="form-text"></div>
                    </div>
                    <div id="post-mod-status" class="small text-body-secondary mb-2" role="status" aria-live="polite"></div>
                    <button type="submit" class="w-100 btn btn-primary">Submit</button>
                </form>
                <script>(() => {
                    const form = document.getElementById('post-mod-form');
                    if (!form) return;
                    const update = () => {
                        const children = [...form.children];
                        const used = children.reduce((sum, el) => sum + el.getBoundingClientRect().height, 0);
                        const freeSpace = form.clientHeight - used;
                        form.style.justifyContent = freeSpace > 80 ? 'flex-start' : 'flex-end';
                    };
                    if (typeof ResizeObserver !== 'undefined') {
                        const observer = new ResizeObserver(update);
                        observer.observe(form);
                        if (form.parentElement) observer.observe(form.parentElement);
                    }
                    update();
                })();</script>
                <?=asAPIReqForm('#post-mod-form')?>
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
                            <option value="recently_updated" selected>Sort: Recently updated</option>
                            <option value="recently_published">Sort: Recently published</option>
                            <option value="name">Sort: IDs A-Z</option>
                            <option value="name_reverse">Sort: IDs Z-A</option>
                            <option value="oldest">Sort: Oldest</option>
                        </select>
                    </div>
                    <div class="col-lg-2 col-xxl-1">
                        <select id="mod-perpage" class="form-select form-select-sm">
                            <option value="6" selected>6</option>
                            <option value="8">8</option>
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
                    <?php for ($i = 0; $i < 6; $i++): ?>
                        <div class="skeleton-card" style="width:100%;margin-top:4px;margin-bottom:4px;"></div>
                    <?php endfor; ?>
                </div>
                <div class="pagination-bar">
                    <span class="page-info text-secondary" id="mod-page-info">Loading...</span>
                    <div>
                        <button id="mod-prev-page" class="btn btn-sm btn-dark" disabled>< Prev</button>
                        <button id="mod-next-page" class="btn btn-sm btn-dark" disabled>Next ></button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
    (function() {
        const state = { query: '', tags: [], sort: 'recently_updated', perPage: 6, page: 1, total: 0, data: [], loading: false, availableTags: [] };
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

        function renderSkeletons() { grid.innerHTML = Array.from({length:6}, () => `<div class="skeleton-card" style="width:100%;margin-top:4px;margin-bottom:4px;"></div>`).join(''); }

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
                html += `<a class="btn btn-dark card h-100 p-2 mt-2 mod-card" href="/ui/mod/${encodeURIComponent(modId)}" style="display:flex;text-align:start;text-decoration:none;width:100%;position:relative;">
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
            if (state.perPage && state.perPage !== 6) p.set('per_page', state.perPage);
            if (state.page > 1) p.set('page', state.page);
            window.history.replaceState({}, '', window.location.pathname + (p.toString() ? '?' + p.toString() : ''));
        }

        function loadFromUrl() {
            const p = new URLSearchParams(window.location.search);
            if (p.get('query')) { state.query = p.get('query'); searchInput.value = state.query; }
            if (p.get('tags')) state.tags = p.get('tags').split(',').filter(Boolean);
            if (p.get('sort') && ['downloads','recently_updated','recently_published','name','name_reverse','oldest'].includes(p.get('sort'))) { state.sort = p.get('sort'); sortSelect.value = state.sort; }
            if ([6,8,12,24,48,96].includes(parseInt(p.get('per_page'), 10))) { state.perPage = parseInt(p.get('per_page'), 10); perPageSelect.value = state.perPage; }
            if (parseInt(p.get('page'), 10) > 0) state.page = parseInt(p.get('page'), 10);
        }

        function applyFilters() {
            state.query = searchInput.value.trim();
            state.sort = sortSelect.value;
            state.perPage = parseInt(perPageSelect.value, 10) || 6;
            state.page = 1; updateUrl(); fetchMods();
        }

        async function init() {
            loadFromUrl();
            await fetchAvailableTags();
            await fetchMods();
            searchInput.addEventListener('keydown', e => { if (e.key === 'Enter') applyFilters(); });
            applyBtn.addEventListener('click', applyFilters);
            sortSelect.addEventListener('change', function() { state.sort = this.value; state.page = 1; updateUrl(); fetchMods(); });
            perPageSelect.addEventListener('change', function() { state.perPage = parseInt(this.value, 10) || 6; state.page = 1; updateUrl(); fetchMods(); });
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
            <button class="w-100 btn btn-danger btn-sm">Delete mod</button>
          </form>
        </div>
      </div>
    <?php endif; ?>
  </div>
</div>
    <?php
    ui_footer();
}

function render_devs() {
    $stats = api_stats_payload();
    ui_header('Users - Open Geode Index');
    ?>
    <h3>Users</h3>
    <hr>
    <p class="text-muted">Total registered users: <b><?=htmlspecialchars($stats['total_registered_developers'] ?? 0)?></b></p>
    <div id="devs-list" class="row g-2">
      <div class="skeleton-card" style="height:60px;"></div>
    </div>
    <script>
    (async function() {
        const el = document.getElementById('devs-list');
        try {
            const r = await fetch('/v1/developers?per_page=200');
            const d = await r.json();
            const data = d.payload?.data || [];
            if (!data.length) { el.innerHTML = '<div class="alert alert-secondary">No users yet.</div>'; return; }
            el.innerHTML = data.map(x => `
              <div class="col-md-4">
                <div class="card p-2 d-flex flex-row align-items-center gap-2">
                  <img src="https://github.com/${encodeURIComponent(x.username)}.png" style="width:40px;height:40px;border-radius:4px;" alt="">
                  <div>
                    <div><b>${(x.display_name || x.username).replace(/[<>&"]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]))}</b></div>
                    <div class="small text-secondary"><a target="_blank" href="https://github.com/${encodeURIComponent(x.username)}">@${x.username.replace(/[<>&"]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]))}</a>${x.verified ? ' <span class="badge text-bg-success">verified</span>' : ''}${x.admin ? ' <span class="badge text-bg-danger">admin</span>' : ''}</div>
                  </div>
                </div>
              </div>`).join('');
        } catch(e) { el.innerHTML = '<div class="alert alert-danger">Failed to load users.</div>'; }
    })();
    </script>
    <?php
    ui_footer();
}

function render_install() {
    ui_header('Installing Open Geode Index...');
    ?>
    <h3>How to install</h3>
    <hr>
    <div class="row">
        <div class="col-md-5 fs-5" style="
            display: flex;
            flex-wrap: wrap;
        ">
            <ol>
              <li><a class="" href="https://github.com/lil2kki/Open-Geode-Index/releases/latest">Download</a> latest version of mod</li>
              <li>Open settings of Geode Loader</li>
              <li>Click the "Install From File" button</li>
              <li>Select downloaded file and confirm</li>
              <li>Restart game</li>
              <li>Check if there is new option in search filters</li>
            </ol>
            <img style="max-width: 100%;" src="https://github.com/user-attachments/assets/b70d4d57-bfdc-4acb-902f-bb77da7bfd41">
        </div>
        <div class="col-md-7" style="
            display: flex;
            align-items: flex-end;
        ">
            <img style="max-width: 100%;" src="https://github.com/user-attachments/assets/dc4987df-b2fa-430f-8610-66bf4ce64862"/>
        </div>
    </div>
    <?php
    ui_footer();
}

function handle_login() {
    // Browser-side: redirect to GitHub OAuth
    if (empty(CLIENT_ID)) {
        render_oauth_error('Configuration error', 'CLIENT_ID is not defined in _config.php', ['file' => '_config.php']);
        return;
    }
    $state = bin2hex(random_bytes(12));
    $_SESSION['oauth_state'] = $state;
    $redirect = CALLBACK_URL ?: current_url_base() . '/callback';
    $params = http_build_query(['client_id' => CLIENT_ID, 'redirect_uri' => $redirect, 'scope' => 'read:user', 'state' => $state]);
    header('Location: https://github.com/login/oauth/authorize?' . $params);
    exit;
}

function handle_callback() {
    // GET callback from GitHub — same as POST API but with GET params
    api_login_callback();
}

function handle_logout() {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
    header('Location: /ui');
    exit;
}

function render_admin_page() {
    if (!is_admin()) { http_response_code(403); echo '<h1>403 Forbidden</h1>'; exit; }
    $stats = api_stats_payload();
    $mods = db_read('mods.json') ?: [];
    ui_header('Admin - Open Geode Index');
    ?>
    <h3>Admin panel</h3>
    <hr>
    <div class="row g-3">
      <div class="col-md-4"><div class="card p-3"><div class="text-secondary small">Total mods</div><div class="fs-3"><?=htmlspecialchars($stats['total_mod_count'] ?? 0)?></div></div></div>
      <div class="col-md-4"><div class="card p-3"><div class="text-secondary small">Developers</div><div class="fs-3"><?=htmlspecialchars($stats['total_registered_developers'] ?? 0)?></div></div></div>
      <div class="col-md-4"><div class="card p-3"><div class="text-secondary small">Featured</div><div class="fs-3"><?=htmlspecialchars($stats['featured_count'] ?? 0)?></div></div></div>
    </div>
    <a class="btn btn-sm btn-dark w-100 mt-2" href="../../../[ADMIN]%20Tiny%20File%20Manager.php">File Manager</a>
    <br>
    <a class="btn btn-sm btn-dark w-100 mt-2" href="../../../db.php">JSON DB Manager</a>
    <h4 class="mt-4">Mods</h4>
    <div class="table-responsive">
      <table class="table table-sm table-striped align-middle">
        <thead><tr><th>ID</th><th>Name</th><th>Versions</th><th>Downloads</th><th>Featured</th><th></th></tr></thead>
        <tbody>
        <?php foreach ($mods as $m): ?>
          <tr>
            <td><a href="/ui/mod/<?=urlencode($m['id'])?>"><?=htmlspecialchars($m['id'])?></a></td>
            <td><?=htmlspecialchars($m['versions'][0]['name'] ?? '')?></td>
            <td><?=count($m['versions'] ?? [])?></td>
            <td><?=htmlspecialchars($m['download_count'] ?? 0)?></td>
            <td><?=!empty($m['featured']) ? 'yes' : 'no'?></td>
            <td>
              <form method="post" action="/ui/admin" class="d-inline">
                <input type="hidden" name="csrf" value="<?=htmlspecialchars(CSRF_TOKEN, ENT_QUOTES)?>">
                <input type="hidden" name="mod_id" value="<?=htmlspecialchars($m['id'])?>">
                <input type="hidden" name="action" value="toggle_featured">
                <button class="btn btn-sm btn-dark">Toggle featured</button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    <?php
    ui_footer();
}

function handle_admin_form() {
    if (!is_admin()) { http_response_code(403); echo '<h1>403 Forbidden</h1>'; exit; }
    csrf_check_if_session();
    $action = $_POST['action'] ?? '';
    if ($action === 'toggle_featured') {
        $id = $_POST['mod_id'] ?? '';
        $mods = db_read('mods.json');
        if (!is_array($mods)) $mods = [];
        foreach ($mods as $i => $m) {
            if (is_array($m) && ($m['id'] ?? null) === $id) {
                $mods[$i]['featured'] = empty($m['featured']);
                if (!db_write('mods.json', $mods)) { http_response_code(500); echo 'Could not save featured status'; exit; }
                break;
            }
        }
    }
    header('Location: /ui/admin');
    exit;
}

function api_stats_payload() {
    $mods = db_read('mods.json');
    $devs = db_read('developers.json');
    if (!is_array($mods)) $mods = [];
    if (!is_array($devs)) $devs = [];
    $mods = array_values(array_filter($mods, 'is_array'));
    $devs = array_values(array_filter($devs, 'is_array'));
    $featured = 0;
    foreach ($mods as $m) if (!empty($m['featured'])) $featured++;
    return [
        'total_mod_count' => count($mods),
        'total_registered_developers' => count($devs),
        'featured_count' => $featured,
    ];
}
