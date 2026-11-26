<?php
session_start([
    'cookie_httponly'  => true,
    'cookie_samesite'  => 'Strict',
    'use_strict_mode'  => true,
    'gc_maxlifetime'   => 1800,         // 30-min idle expiry
]);

// Regenerate session ID on every request to prevent fixation
if (empty($_SESSION['_init'])) {
    session_regenerate_id(true);
    $_SESSION['_init'] = true;
}

// Hardened cache / security headers
header('Cache-Control: no-store, no-cache, must-revalidate, private');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');

// ── CSRF helper ──────────────────────────────────────────────
function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}
function csrf_valid(): bool {
    $tok = $_POST['csrf_token'] ?? '';
    return !empty($tok) && hash_equals($_SESSION['csrf_token'] ?? '', $tok);
}

// ── Password (stored hash only — never plaintext) ────────────
// Default credential: admin123
// Regenerate with: php -r "echo password_hash('yourpassword', PASSWORD_ARGON2ID);"
const HASHED_PASSWORD = '$argon2id$v=19$m=65536,t=4,p=1$UTNSTnY0eHdUZlJ2TEtQRw$Cg4GLepFW/pEq+tLPrkB7WDfgU+YvUfgd2Rx69G5oTk';


// ── Rate-limiting via session (keyed by hashed IP) ───────────
$ipKey    = hash('sha256', $_SERVER['REMOTE_ADDR'] . ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
$ratePath = 'login_attempts';

if (!isset($_SESSION[$ratePath][$ipKey])) {
    $_SESSION[$ratePath][$ipKey] = ['count' => 0, 'first' => time(), 'locked_until' => 0];
}
$ra  = &$_SESSION[$ratePath][$ipKey];
$now = time();

// Reset window if 24 h have passed since the first attempt
if ($now - $ra['first'] > 86400) {
    $ra = ['count' => 0, 'first' => $now, 'locked_until' => 0];
}

// ── Auth state ───────────────────────────────────────────────
$isAuthenticated = !empty($_SESSION['authenticated']);
$isLocked        = $ra['locked_until'] > $now;
$error           = null;

// ── Handle login POST ──────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password']) && !$isAuthenticated && !$isLocked) {

    if (!csrf_valid()) {
        $error = 'Invalid request. Please refresh and try again.';
    } else {
        // Regenerate CSRF after each attempt
        unset($_SESSION['csrf_token']);

        $pw = $_POST['password'] ?? '';

        if (is_string($pw) && strlen($pw) > 0 && strlen($pw) <= 128 && password_verify($pw, HASHED_PASSWORD)) {
            session_regenerate_id(true);           // Privilege escalation: new session
            $_SESSION['authenticated'] = true;
            $_SESSION['auth_time']     = $now;
            $isAuthenticated           = true;
            $ra = ['count' => 0, 'first' => $now, 'locked_until' => 0];
        } else {
            $ra['count']++;

            if ($ra['count'] >= 10) {
                $ra['locked_until'] = $now + 86400;
                $error = 'Account locked for 24 hours due to too many failed attempts.';
            } elseif ($ra['count'] >= 5) {
                $ra['locked_until'] = $now + 300;
                $error = 'Too many attempts. Please wait 5 minutes.';
            } else {
                $left  = 5 - $ra['count'];
                $error = "Incorrect password. $left attempt(s) remaining before lockout.";
            }
        }
    }
}

// Re-check lock (after POST may have just set it)
$isLocked = $ra['locked_until'] > $now;
if ($isLocked && !$error) {
    $mins  = ceil(($ra['locked_until'] - $now) / 60);
    $error = "Access locked. Try again in {$mins} minute(s).";
}

// ── Absolute session age (force re-auth after 30 min) ────────
if ($isAuthenticated && isset($_SESSION['auth_time']) && ($now - $_SESSION['auth_time'] > 1800)) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// ── Logout (must be before any HTML output) ─────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout']) && csrf_valid()) {
    session_unset();
    session_destroy();
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict',
        'use_strict_mode' => true,
    ]);
    session_regenerate_id(true);
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// ── File search (authenticated only) ─────────────────────────
$searchResults = [];
$searchQuery   = '';
$searched      = false;

$excludedFiles = [
    '.htaccess', '.htpasswd', 'config.php', 'settings.php',
    'database.php', 'admin.php', 'viewer.aspx'
];
$excludedDirs = ['.private', '.archive', '.git', 'node_modules', 'vendor'];

function searchFiles(string $dir, string $query, array $excludedFiles, array $excludedDirs): array {
    $results = [];
    try {
        $items = @scandir($dir);
        if ($items === false) return $results;
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            if (in_array($item, $excludedFiles) || in_array($item, $excludedDirs)) continue;
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $results = array_merge($results, searchFiles($path, $query, $excludedFiles, $excludedDirs));
            } elseif (stripos($item, $query) !== false) {
                $results[] = $path;
            }
        }
    } catch (Throwable) { /* silently skip unreadable dirs */ }
    return $results;
}

function getRelativePath(string $abs): string {
    $root = realpath($_SERVER['DOCUMENT_ROOT'] ?? '') ?: '';
    return $root ? str_replace($root, '', $abs) : $abs;
}

if ($isAuthenticated && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['search']) && csrf_valid()) {
    $raw         = trim($_POST['search'] ?? '');
    $searchQuery = preg_replace('/[^a-zA-Z0-9._\- ]/', '', $raw); // sanitize
    $searched    = true;
    if (strlen($searchQuery) >= 3) {
        $searchResults = searchFiles(__DIR__, $searchQuery, $excludedFiles, $excludedDirs);
    }
}

// Viewer routing: PDF->Google, Office->Microsoft
$pdfExts       = ['pdf'];
$officeExts    = ['doc','docx','odt','ppt','pptx','odp','xls','xlsx','ods'];
$docViewerExts = array_merge($pdfExts, $officeExts);

$iconData = [
    'pdf'  => ['fa-file-pdf',       '#F87171'],
    'doc'  => ['fa-file-word',      '#60A5FA'],
    'docx' => ['fa-file-word',      '#60A5FA'],
    'odt'  => ['fa-file-word',      '#60A5FA'],
    'xls'  => ['fa-file-excel',     '#34D399'],
    'xlsx' => ['fa-file-excel',     '#34D399'],
    'ods'  => ['fa-file-excel',     '#34D399'],
    'ppt'  => ['fa-file-powerpoint','#FB923C'],
    'pptx' => ['fa-file-powerpoint','#FB923C'],
    'odp'  => ['fa-file-powerpoint','#FB923C'],
    'jpg'  => ['fa-file-image',     '#A78BFA'],
    'jpeg' => ['fa-file-image',     '#A78BFA'],
    'png'  => ['fa-file-image',     '#A78BFA'],
    'gif'  => ['fa-file-image',     '#A78BFA'],
    'webp' => ['fa-file-image',     '#A78BFA'],
    'svg'  => ['fa-file-image',     '#FBBF24'],
    'zip'  => ['fa-file-zipper',    '#94A3B8'],
    'rar'  => ['fa-file-zipper',    '#94A3B8'],
    '7z'   => ['fa-file-zipper',    '#94A3B8'],
    'php'  => ['fa-file-code',      '#C084FC'],
    'js'   => ['fa-file-code',      '#FDE047'],
    'ts'   => ['fa-file-code',      '#5EAAF2'],
    'html' => ['fa-file-code',      '#F0724F'],
    'css'  => ['fa-file-code',      '#5B7FF2'],
    'txt'  => ['fa-file-lines',     '#9CA3AF'],
    'md'   => ['fa-file-lines',     '#9CA3AF'],
    'mp4'  => ['fa-file-video',     '#FB7185'],
    'mp3'  => ['fa-file-audio',     '#2DD4BF'],
    'wav'  => ['fa-file-audio',     '#2DD4BF'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="robots" content="noindex, nofollow" />
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%2064%2064%22%3E%3Crect%20width%3D%2264%22%20height%3D%2264%22%20rx%3D%2214%22%20fill%3D%22%23c8981e%22%2F%3E%3Cg%20transform%3D%22translate%2815%2C15%29%20scale%281.417%29%22%3E%3Cpath%20d%3D%22M20%206h-2.18A3%203%200%200%200%2015%204H9a3%203%200%200%200-2.82%202H4a2%202%200%200%200-2%202v10a2%202%200%200%200%202%202h16a2%202%200%200%200%202-2V8a2%202%200%200%200-2-2zM9%206h6v2H9V6zm6%209h-3v3h-2v-3H7v-2h3V10h2v3h3v2z%22%20fill%3D%22%230f1f38%22%2F%3E%3C%2Fg%3E%3C%2Fsvg%3E">
<title>DeX</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" />
<script>
// Apply saved theme before first paint to avoid a flash of the wrong theme.
(function(){
  try{
    var t = localStorage.getItem('dd-theme');
    if(!t){ t = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; }
    document.documentElement.setAttribute('data-theme', t);
  }catch(e){ document.documentElement.setAttribute('data-theme','light'); }
})();
</script>

<style>
:root{
  --navy:#0f1f38;
  --navy-mid:#16294a;
  --navy-deep:#0a1526;
  --gold:#c8981e;
  --gold-light:#e0b040;
  --danger:#c0392b;
  --danger-bg:#fdf0ef;
  --ok:#1d7a4c;

  --bg:#f5f4f0;
  --bg-soft:#ecEAE3;
  --surface:#ffffff;
  --surface-raised:#ffffff;
  --border:#e1ddd2;
  --text:#161b26;
  --text-mid:#4d5568;
  --text-soft:#8b93a3;
  --row-hover:#f9f7f2;

  --font-display:'Noto Sans',sans-serif;
  --font-body:'Noto Sans',sans-serif;
  --font-mono:'Noto Sans',sans-serif;

  --radius-sm:10px;
  --radius-md:16px;
  --radius-lg:20px;
  --shadow-sm:0 1px 2px rgba(15,31,56,.04);
  --shadow-md:0 8px 24px rgba(15,31,56,.06);
  --shadow-lg:0 20px 48px rgba(15,31,56,.14);
  --transition:.2s cubic-bezier(.4,0,.2,1);
  --maxw:1180px;
}
:root[data-theme="dark"]{
  --bg:#0b1424;
  --bg-soft:#0f1c30;
  --surface:#101f36;
  --surface-raised:#132441;
  --border:#22385a;
  --text:#eef1f6;
  --text-mid:#a9b4c8;
  --text-soft:#6d7c96;
  --row-hover:#152a49;
  --danger-bg:#3a1a17;
  --shadow-sm:0 1px 2px rgba(0,0,0,.3);
  --shadow-md:0 8px 24px rgba(0,0,0,.35);
  --shadow-lg:0 24px 56px rgba(0,0,0,.5);
}
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box;}
html{scroll-behavior:smooth;height:100%;}
body{
  font-family:var(--font-body);
  font-weight:400;
  background:var(--bg);
  color:var(--text);
  min-height:100vh;
  min-height:100dvh;
  padding-bottom:48px;
  overflow-x:hidden;
  -webkit-font-smoothing:antialiased;
  transition:background var(--transition),color var(--transition);
}
body.no-scroll{height:100vh;height:100dvh;overflow:hidden;padding-bottom:0;}
img,svg{display:block;}
button,input{font-family:inherit;}
h1,h2,h3,.brand h1,.section-label h2,.results-header h3,.lock-state h3{font-family:var(--font-display);}

/* ── Top bar ─────────────────────────────────────────── */
.topbar{
  position:sticky;top:0;z-index:100;
  background:var(--navy);
  border-bottom:1px solid rgba(255,255,255,.08);
}
.topbar-inner{
  max-width:var(--maxw);margin:0 auto;
  display:flex;align-items:center;justify-content:space-between;
  height:56px;padding:0 20px;gap:12px;
}
.brand{display:flex;align-items:center;gap:10px;min-width:0;}
.brand-icon{
  width:36px;height:36px;flex-shrink:0;border-radius:10px;
  background:var(--gold);
  display:flex;align-items:center;justify-content:center;
  position:relative;overflow:hidden;
}
.brand-icon svg{width:19px;height:19px;fill:var(--navy);position:relative;z-index:1;}
.brand h1{
  font-size:1.02rem;font-weight:700;color:#fff;letter-spacing:.01em;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.status-pill{
  display:flex;align-items:center;gap:7px;
  font-size:.76rem;font-weight:600;color:rgba(255,255,255,.72);
  padding:6px 12px;border-radius:20px;background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.10);white-space:nowrap;
}
.status-pill .dot{width:7px;height:7px;border-radius:50%;background:var(--ok);}
.status-pill.locked .dot{background:var(--text-soft);box-shadow:none;}
.signout-btn{
  display:flex;align-items:center;gap:7px;
  font-size:.78rem;font-weight:600;color:var(--gold-light);
  background:rgba(200,152,30,.10);border:1px solid rgba(200,152,30,.28);
  padding:7px 13px;border-radius:9px;cursor:pointer;transition:background var(--transition);
}
.signout-btn:hover{background:rgba(200,152,30,.20);}
.theme-toggle{
  width:32px;height:32px;border-radius:9px;flex-shrink:0;
  background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.10);
  color:var(--gold-light);cursor:pointer;
  display:flex;align-items:center;justify-content:center;font-size:.82rem;
  transition:background var(--transition);
}
.theme-toggle:hover{background:rgba(255,255,255,.14);}
.theme-toggle i{transition:transform .35s cubic-bezier(.4,0,.2,1),opacity .18s ease;}
:root.theme-transitioning,
:root.theme-transitioning *{
  transition:background-color .4s ease,color .4s ease,border-color .4s ease,fill .4s ease!important;
}

/* ── Layout shell ────────────────────────────────────── */
.shell{
  max-width:var(--maxw);margin:0 auto;padding:28px 20px 0;
  display:grid;grid-template-columns:280px 1fr;gap:24px;
  align-items:start;
}
@media (max-width:900px){
  .shell{grid-template-columns:1fr;}
  .side{display:none;}
}

/* ── Side panel ──────────────────────────────────────── */
.side{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius-lg);padding:22px 20px;
  box-shadow:var(--shadow-sm);position:sticky;top:80px;
}
.side h2{font-size:1.02rem;font-weight:700;margin-bottom:6px;}
.side p{font-size:.83rem;color:var(--text-mid);line-height:1.5;margin-bottom:16px;}
.side-divider{height:1px;background:var(--border);margin:16px 0;}
.side-row{
  display:flex;align-items:center;gap:10px;font-size:.82rem;
  color:var(--text-mid);padding:7px 0;
}
.side-row i{width:16px;text-align:center;color:var(--gold);font-size:.85rem;}

/* ── Main card ───────────────────────────────────────── */
.main{min-width:0;}
.card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--radius-lg);box-shadow:var(--shadow-md);
  overflow:hidden;
}
.card-body{padding:32px 32px 28px;}
@media (max-width:600px){.card-body{padding:22px 18px 20px;}}

.section-label{display:flex;align-items:flex-start;gap:14px;margin-bottom:22px;}
.icon-wrap{
  width:48px;height:48px;flex-shrink:0;border-radius:14px;
  background:var(--navy);
  display:flex;align-items:center;justify-content:center;color:var(--gold-light);
  font-size:1.15rem;
  position:relative;overflow:hidden;
}
.icon-wrap i{position:relative;z-index:1;}
.section-label h2{font-size:1.15rem;font-weight:800;margin-bottom:2px;}
.section-label p{font-size:.86rem;color:var(--text-soft);}

/* ── Alerts ──────────────────────────────────────────── */
.alert{
  display:flex;align-items:flex-start;gap:10px;
  padding:12px 14px;border-radius:var(--radius-sm);
  font-size:.85rem;font-weight:500;margin-bottom:18px;
  animation:fadeDown .25s ease;
}
.alert-error{background:var(--danger-bg);color:var(--danger);border:1px solid var(--danger);}
.alert i{margin-top:2px;flex-shrink:0;}

/* ── Form fields ─────────────────────────────────────── */
.field{
  position:relative;display:flex;align-items:center;
  border:1.5px solid var(--border);border-radius:var(--radius-sm);
  background:var(--bg-soft);transition:border-color var(--transition),background var(--transition);
}
.field:focus-within{border-color:var(--gold);background:var(--surface);}
.field-icon{padding:0 14px;color:var(--text-soft);font-size:.9rem;}
.field input{
  flex:1;border:none;background:transparent;outline:none;
  padding:13px 6px;font-size:.95rem;color:var(--text);min-width:0;
}
.eye-toggle{
  background:none;border:none;padding:0 14px;cursor:pointer;
  color:var(--text-soft);font-size:.9rem;
}
.eye-toggle:hover{color:var(--text-mid);}

.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  font-size:.9rem;font-weight:700;border:none;border-radius:var(--radius-sm);
  padding:13px 20px;cursor:pointer;transition:transform var(--transition),box-shadow var(--transition),background var(--transition);
  width:100%;margin-top:14px;
}
.btn-primary{
  background:linear-gradient(135deg,var(--gold-light),var(--gold));
  color:var(--navy);
}
.btn-primary:hover{transform:translateY(-1px);}
.btn-primary:active{transform:translateY(0);}
.btn-ghost{background:var(--bg-soft);color:var(--text-mid);border:1px solid var(--border);}
.btn-ghost:hover{background:var(--border);}
.btn-sm{width:auto;padding:9px 14px;font-size:.8rem;margin-top:0;}
.btn[disabled]{opacity:.6;cursor:not-allowed;transform:none !important;}

/* ── Search ──────────────────────────────────────────── */
.search-row{
  display:flex;gap:10px;border:1.5px solid var(--border);
  border-radius:var(--radius-sm);background:var(--bg-soft);
  align-items:center;padding:4px 4px 4px 14px;
  transition:border-color var(--transition),background var(--transition);
  flex-wrap:wrap;
}
.search-row:focus-within{border-color:var(--gold);background:var(--surface);}
.search-icon{color:var(--text-soft);font-size:.9rem;flex-shrink:0;}
.search-row input{
  flex:1;min-width:120px;border:none;background:transparent;outline:none;
  padding:12px 6px;font-size:.95rem;color:var(--text);
}
.search-submit{
  display:flex;align-items:center;gap:7px;
  background:var(--navy);color:#fff;border:none;
  border-radius:9px;padding:11px 18px;font-size:.85rem;font-weight:700;
  cursor:pointer;transition:background var(--transition);flex-shrink:0;
}
.search-submit:hover{background:var(--navy-mid);}
.search-submit[disabled]{opacity:.6;cursor:not-allowed;}

.divider{
  display:flex;align-items:center;gap:12px;margin:22px 0 14px;
  color:var(--text-soft);font-size:.75rem;font-weight:700;
  text-transform:uppercase;letter-spacing:.06em;
}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border);}

.results-header{
  display:flex;align-items:center;justify-content:space-between;
  margin:24px 0 12px;gap:10px;flex-wrap:wrap;
}
.results-header h3{font-size:.92rem;font-weight:700;word-break:break-word;}
.badge{
  font-size:.72rem;font-weight:700;background:var(--gold-light);
  color:var(--navy);padding:4px 10px;border-radius:20px;white-space:nowrap;
}

.table-wrap{border:1px solid var(--border);border-radius:var(--radius-md);overflow:hidden;background:var(--surface);}
.result-table{width:100%;border-collapse:collapse;font-size:.86rem;}
.result-table thead th{
  text-align:left;font-family:var(--font-body);font-weight:600;font-size:.74rem;
  color:var(--text-soft);padding:11px 14px;background:var(--bg-soft);
  border-bottom:1px solid var(--border);white-space:nowrap;
}
.result-table thead th.col-type{width:110px;}
.result-table thead th.col-action{width:56px;}
.result-table tbody tr{
  cursor:pointer;transition:background var(--transition);
  animation:fadeUp .3s ease both;
}
.result-table tbody tr:not(:last-child) td{border-bottom:1px solid var(--border);}
.result-table tbody tr:hover{background:var(--row-hover);}
.result-table td{padding:10px 14px;vertical-align:middle;}
.result-table td.col-name{display:flex;align-items:center;gap:12px;min-width:0;}
.file-icon{
  width:34px;height:34px;flex-shrink:0;border-radius:9px;
  display:flex;align-items:center;justify-content:center;font-size:.95rem;
  position:relative;overflow:hidden;background:var(--navy)!important;
}
.file-icon i{position:relative;z-index:1;filter:brightness(1.15);}
.file-name{font-size:.86rem;font-weight:600;word-break:break-all;color:var(--text);}
.file-path{font-size:.72rem;color:var(--text-soft);margin-top:1px;word-break:break-all;font-family:var(--font-mono);}
.type-chip{
  font-family:var(--font-mono);font-size:.68rem;font-weight:500;
  color:var(--text-mid);background:var(--bg-soft);border:1px solid var(--border);
  padding:3px 8px;border-radius:6px;text-transform:uppercase;letter-spacing:.02em;
}
.open-icon{color:var(--text-soft);font-size:.75rem;opacity:0;transition:opacity var(--transition);}
.result-table tbody tr:hover .open-icon{opacity:1;}
@media (max-width:640px){
  .result-table thead{display:none;}
  .result-table, .result-table tbody, .result-table tr, .result-table td{display:block;width:100%;}
  .result-table tbody tr{padding:10px 12px;border-bottom:1px solid var(--border);}
  .result-table td{padding:2px 0;border:none !important;}
  .result-table td.col-action{display:none;}
}

.empty-state{text-align:center;padding:36px 20px;color:var(--text-soft);}
.empty-state i{font-size:2.2rem;color:var(--border);margin-bottom:14px;display:block;}
.empty-state p{font-size:.9rem;}
.empty-state strong{color:var(--text-mid);}

.auth-footer{
  display:flex;align-items:center;justify-content:center;gap:6px;
  padding:12px 24px;background:var(--bg-soft);border-top:1px solid var(--border);
  font-size:.76rem;color:var(--text-soft);text-align:center;
}
.auth-footer strong{color:var(--text);}

/* ── Lock state ──────────────────────────────────────── */
.lock-state{text-align:center;padding:20px 0 6px;}
.lock-icon{
  width:72px;height:72px;background:var(--danger-bg);
  border:1px solid var(--danger);border-radius:50%;
  display:flex;align-items:center;justify-content:center;margin:0 auto 22px;
  position:relative;
}
.lock-icon i{font-size:1.75rem;color:var(--danger);}
.lock-state h3{font-size:1.1rem;font-weight:800;margin-bottom:8px;}
.lock-state p{font-size:.88rem;color:var(--text-soft);max-width:340px;margin:0 auto;line-height:1.6;}

/* ── Modal / document viewer ─────────────────────────── */
.modal-backdrop{
  display:none;position:fixed;inset:0;background:rgba(10,20,40,.72);
  backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);
  z-index:9000;align-items:center;justify-content:center;padding:12px;
  animation:fadeIn .2s ease;
}
.modal-backdrop.open{display:flex;}
.modal-box{
  width:100%;max-width:960px;height:calc(100vh - 24px);max-height:920px;
  background:var(--navy);border-radius:var(--radius-md);overflow:hidden;
  display:flex;flex-direction:column;
  animation:scaleIn .22s ease;position:relative;
}
@media (max-width:600px){
  .modal-backdrop{padding:0;}
  .modal-box{height:100vh;max-height:none;border-radius:0;}
}
.modal-bar{
  display:flex;align-items:center;justify-content:space-between;
  padding:10px 12px;background:var(--navy-mid);
  border-bottom:1px solid rgba(255,255,255,.07);gap:10px;flex-shrink:0;
}
.modal-bar-left{display:flex;align-items:center;gap:8px;min-width:0;overflow:hidden;}
.modal-bar-right{display:flex;align-items:center;gap:5px;flex-shrink:0;}
.modal-file-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}
.modal-title{
  font-size:.82rem;color:rgba(255,255,255,.85);font-weight:600;
  display:flex;align-items:center;gap:6px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap;
}
.modal-viewer-badge{
  font-size:.62rem;font-weight:700;padding:2px 7px;border-radius:20px;
  border:1px solid;letter-spacing:.04em;white-space:nowrap;flex-shrink:0;
}
.modal-action-btn{
  width:28px;height:28px;background:rgba(255,255,255,.07);
  border:1px solid rgba(255,255,255,.1);border-radius:7px;
  color:rgba(255,255,255,.55);cursor:pointer;
  display:flex;align-items:center;justify-content:center;font-size:.75rem;
  transition:all var(--transition);
}
.modal-action-btn:hover{background:rgba(255,255,255,.14);color:#fff;}
.btn-close{
  width:30px;height:30px;background:rgba(255,255,255,.08);border:none;
  border-radius:50%;color:#fff;cursor:pointer;
  display:flex;align-items:center;justify-content:center;font-size:.85rem;
  transition:background var(--transition);flex-shrink:0;
}
.btn-close:hover{background:rgba(192,57,43,.6);}

.viewer-loading,.viewer-error{
  position:absolute;inset:0;top:48px;display:flex;flex-direction:column;
  align-items:center;justify-content:center;gap:12px;background:var(--navy);
  z-index:5;text-align:center;padding:24px;
}
.viewer-spinner{
  width:38px;height:38px;border:3px solid rgba(255,255,255,.1);
  border-top-color:var(--gold);border-radius:50%;
  animation:spin .8s linear infinite;margin-bottom:4px;
}
@keyframes spin{to{transform:rotate(360deg);}}
.viewer-loading p{color:rgba(255,255,255,.75);font-size:.9rem;font-weight:600;}
.viewer-loading-sub{color:rgba(255,255,255,.35) !important;font-size:.75rem !important;margin-top:-4px;}
.viewer-error-icon{
  width:52px;height:52px;background:var(--danger-bg);
  border:2px solid var(--danger);border-radius:50%;
  display:flex;align-items:center;justify-content:center;
}
.viewer-error-icon i{font-size:1.3rem;color:var(--danger);}
.viewer-error p{color:rgba(255,255,255,.8);font-size:.88rem;font-weight:600;}
.viewer-error-sub{color:rgba(255,255,255,.38) !important;font-size:.76rem !important;margin-top:-4px;}
.viewer-error-btns{display:flex;gap:8px;margin-top:6px;flex-wrap:wrap;justify-content:center;}
#modal-frame{
  position:absolute;inset:0;top:48px;width:100%;height:calc(100% - 48px);
  border:none;background:#fff;opacity:0;pointer-events:none;
  transition:opacity .3s ease;
}

/* ── Animations ──────────────────────────────────────── */
@keyframes fadeUp{from{opacity:0;transform:translateY(12px);}to{opacity:1;transform:translateY(0);}}
@keyframes fadeDown{from{opacity:0;transform:translateY(-8px);}to{opacity:1;transform:translateY(0);}}
@keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
@keyframes scaleIn{from{opacity:0;transform:scale(.96);}to{opacity:1;transform:scale(1);}}

/* ── Mobile bottom nav (replaces sidebar on small screens) ─ */
.mobile-bar{display:none;}
@media (max-width:900px){
  .shell{padding:18px 14px 0;}
  .card{border-radius:18px;}
  .card-body{padding:20px 16px 16px;}
}
@media (max-width:600px){
  body{padding-bottom:28px;}
  .topbar-inner{height:52px;padding:0 14px;}
  .brand h1{font-size:.92rem;}
  .status-pill{padding:5px 10px;}
  .status-pill span.label{display:none;}
  .signout-btn span{display:none;}
  .signout-btn{padding:7px 10px;}

  .section-label{gap:11px;margin-bottom:18px;}
  .icon-wrap{width:42px;height:42px;border-radius:12px;font-size:1rem;}
  .section-label h2{font-size:1.02rem;}
  .section-label p{font-size:.8rem;}

  .field input{padding:12px 4px;font-size:1rem;}
  .btn{padding:13px 16px;font-size:.88rem;}

  .search-row{padding:3px 3px 3px 12px;border-radius:13px;}
  .search-row input{padding:11px 4px;font-size:.95rem;min-width:0;}
  .search-submit{padding:10px 14px;}
  .search-submit span{display:none;}
  .search-submit i{font-size:.9rem;}

  .result-list li{padding:11px 12px;gap:10px;border-radius:13px;}
  .file-icon{width:36px;height:36px;border-radius:10px;}
  .file-name{font-size:.85rem;}
  .file-path{font-size:.7rem;}

  .results-header h3{font-size:.85rem;}
  .lock-icon{width:60px;height:60px;}
  .lock-state h3{font-size:1rem;}

  .modal-bar{padding:9px 10px;}
  .modal-title{font-size:.78rem;}
  .modal-viewer-badge{display:none !important;}
}
@media (max-width:380px){
  .brand h1{display:none;}
}
/* Short viewports: compact the unauthenticated (login/locked) card so it
   fits one screen without scrolling */
@media (max-height:700px){
  .shell{padding-top:14px;}
  .card-body{padding:20px 24px 18px;}
  .lock-state{padding:10px 0 4px;}
  .lock-icon{width:56px;height:56px;margin-bottom:14px;}
  .lock-icon i{font-size:1.4rem;}
  .section-label{margin-bottom:14px;}
}
@media (max-height:560px){
  .topbar-inner{height:46px;}
  .shell{padding-top:8px;}
  .card-body{padding:14px 18px 12px;}
  .lock-state p,.section-label p{display:none;}
  .lock-icon{width:44px;height:44px;margin-bottom:8px;}
  .field input{padding:9px 4px;}
  .btn{padding:11px 16px;margin-top:8px;}
}
</style>
</head>
<body class="<?= (!$isAuthenticated) ? 'no-scroll' : '' ?>">

<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <div class="brand-icon">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M20 6h-2.18A3 3 0 0 0 15 4H9a3 3 0 0 0-2.82 2H4a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2zM9 6h6v2H9V6zm6 9h-3v3h-2v-3H7v-2h3V10h2v3h3v2z"/>
        </svg>
      </div>
      <h1>DeX</h1>
    </div>
    <div style="display:flex;align-items:center;gap:10px;">
      <span class="status-pill <?= $isAuthenticated ? '' : 'locked' ?>">
        <span class="dot"></span>
        <span class="label"><?= $isAuthenticated ? 'Session active' : 'Locked' ?></span>
      </span>
      <button type="button" class="theme-toggle" id="theme-toggle" aria-label="Toggle dark mode" title="Toggle theme">
        <i class="fa-solid fa-moon" id="theme-icon"></i>
      </button>
      <?php if ($isAuthenticated): ?>
      <form method="POST" style="display:contents;">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
        <input type="hidden" name="logout" value="1">
        <button type="submit" class="signout-btn">
          <i class="fa-solid fa-arrow-right-from-bracket"></i> Sign out
        </button>
      </form>
      <?php endif; ?>
    </div>
  </div>
</header>

<div class="shell">
  <aside class="side">
    <h2>Data Directory</h2>
    <p>Secure file registry with access control and a built-in document viewer.</p>
    <div class="side-divider"></div>
    <div class="side-row"><i class="fa-solid fa-shield-halved"></i> CSRF protected</div>
    <div class="side-row"><i class="fa-solid fa-clock"></i> 30 min session timeout</div>
    <div class="side-row"><i class="fa-solid fa-ban"></i> Lockout after 5 / 10 attempts</div>
    <div class="side-row"><i class="fa-solid fa-eye"></i> PDF &amp; Office viewer</div>
    <div class="side-row"><i class="fa-solid fa-folder-tree"></i> Recursive file search</div>
  </aside>

  <main class="main">
    <div class="card">
      <div class="card-body">

        <?php if ($isLocked && !$isAuthenticated): ?>
        <div class="lock-state">
          <div class="lock-icon"><i class="fa-solid fa-lock"></i></div>
          <h3>Access Temporarily Locked</h3>
          <p><?= htmlspecialchars($error ?? 'Too many failed attempts.') ?></p>
        </div>

        <?php elseif (!$isAuthenticated): ?>
        <div class="section-label">
          <div class="icon-wrap"><i class="fa-solid fa-key"></i></div>
          <div>
            <h2>Authentication Required</h2>
            <p>Enter your access credential to continue</p>
          </div>
        </div>

        <?php if (isset($error) && !$isLocked): ?>
        <div class="alert alert-error" role="alert">
          <i class="fa-solid fa-circle-exclamation"></i>
          <span><?= htmlspecialchars($error) ?></span>
        </div>
        <?php endif; ?>

        <form method="POST" autocomplete="off" novalidate id="login-form">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
          <div class="field">
            <i class="fa-solid fa-lock field-icon"></i>
            <input
              type="password"
              name="password"
              id="pw-input"
              placeholder="Enter password"
              maxlength="128"
              required
              autofocus
              autocomplete="current-password"
            />
            <button type="button" class="eye-toggle" id="eye-btn" aria-label="Toggle visibility">
              <i class="fa-solid fa-eye" id="eye-icon"></i>
            </button>
          </div>
          <button type="submit" class="btn btn-primary" id="login-btn">
            <i class="fa-solid fa-arrow-right-to-bracket"></i>
            Unlock Directory
          </button>
        </form>

        <?php else: ?>
        <div class="section-label">
          <div class="icon-wrap"><i class="fa-solid fa-folder-open"></i></div>
          <div>
            <h2>File Directory</h2>
            <p>Search across all accessible files</p>
          </div>
        </div>

        <form method="POST" id="search-form" autocomplete="off">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(csrf_token()) ?>">
          <div class="search-row">
            <i class="fa-solid fa-magnifying-glass search-icon"></i>
            <input
              type="text"
              name="search"
              id="search-input"
              placeholder="Search files…"
              value="<?= htmlspecialchars($searchQuery) ?>"
              maxlength="120"
              autofocus
            />
            <button type="submit" class="search-submit" id="search-btn">
              <i class="fa-solid fa-magnifying-glass"></i>
              <span>Search</span>
            </button>
          </div>
        </form>

        <?php if ($searched): ?>
          <?php if (strlen($searchQuery) < 3): ?>
          <div class="alert alert-error" role="alert" style="margin-top:20px;">
            <i class="fa-solid fa-circle-exclamation"></i>
            <span>Please enter at least 3 characters.</span>
          </div>

          <?php elseif (empty($searchResults)): ?>
          <div class="divider"><span>Results</span></div>
          <div class="empty-state">
            <i class="fa-solid fa-file-circle-question"></i>
            <p>No files matched "<strong><?= htmlspecialchars($searchQuery) ?></strong>"</p>
          </div>

          <?php else: ?>
          <div class="results-header">
            <h3>Results for "<?= htmlspecialchars($searchQuery) ?>"</h3>
            <span class="badge"><?= count($searchResults) ?> found</span>
          </div>

          <div class="table-wrap">
          <table class="result-table" id="result-list">
            <thead>
              <tr>
                <th>Name</th>
                <th class="col-type">Type</th>
                <th class="col-action"></th>
              </tr>
            </thead>
            <tbody>
            <?php foreach ($searchResults as $i => $absPath):
              $rel        = getRelativePath($absPath);
              $filename   = basename($rel);
              $ext        = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
              $url        = 'https://' . htmlspecialchars($_SERVER['HTTP_HOST']) . $rel;
              $isDoc      = in_array($ext, $docViewerExts);
              $viewerUrl  = null;
              $viewerType = 'none';
              if ($isDoc) {
                  if (in_array($ext, $pdfExts)) {
                      $viewerUrl  = 'https://docs.google.com/viewer?embedded=true&url=' . rawurlencode($url); // google viewer first, avoids no-preview 'open' fallback
                      $viewerType = 'pdf';
                  } else {
                      $viewerUrl  = 'https://view.officeapps.live.com/op/embed.aspx?src=' . rawurlencode($url);
                      $viewerType = 'office';
                  }
              }
              $iconEntry = $iconData[$ext] ?? ['fa-file', '#94A3B8'];
              [$ico, $icoColor] = $iconEntry;
              $delay = min($i * 0.03, 0.4);
              $displayPath = dirname($rel) !== '/' ? dirname($rel) : '';
            ?>
            <tr
              style="animation-delay: <?= $delay ?>s"
              data-href="<?= htmlspecialchars($isDoc ? $viewerUrl : $url) ?>"
              data-modal="<?= $isDoc ? '1' : '0' ?>"
              data-modal-title="<?= htmlspecialchars($filename) ?>"
              data-viewer-type="<?= htmlspecialchars($viewerType) ?>"
              data-raw-url="<?= htmlspecialchars($url) ?>"
              onclick="handleFileClick(this)"
              role="link"
              tabindex="0"
              onkeydown="if(event.key==='Enter') handleFileClick(this)"
            >
              <td class="col-name">
                <div class="file-icon">
                  <i class="fa-solid <?= $ico ?>" style="color:<?= $icoColor ?>;"></i>
                </div>
                <div style="min-width:0;flex:1;">
                  <div class="file-name"><?= htmlspecialchars($filename) ?></div>
                  <?php if ($displayPath): ?>
                  <div class="file-path"><?= htmlspecialchars($displayPath) ?></div>
                  <?php endif; ?>
                </div>
              </td>
              <td class="col-type"><span class="type-chip"><?= htmlspecialchars($ext ?: '—') ?></span></td>
              <td class="col-action"><i class="fa-solid fa-arrow-up-right-from-square open-icon"></i></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
          </div>
          <?php endif; ?>
        <?php endif; ?>
        <?php endif; ?>

      </div><!-- /card-body -->

      <?php if ($isAuthenticated): ?>
      <div class="auth-footer">
        <i class="fa-solid fa-shield-halved" style="color:var(--gold);"></i>
        Session active — use <strong>Sign out</strong> in the top bar when done
      </div>
      <?php endif; ?>
    </div><!-- /card -->
  </main>
</div><!-- /shell -->

<!-- ── Document Viewer Modal ────────────────────────────────── -->
<div class="modal-backdrop" id="modal" role="dialog" aria-modal="true">
  <div class="modal-box">
    <div class="modal-bar">
      <div class="modal-bar-left">
        <div class="modal-file-dot" id="modal-file-dot"></div>
        <span class="modal-title">
          <i class="fa-solid fa-file" id="modal-icon"></i>
          <span id="modal-filename">Document</span>
        </span>
        <span class="modal-viewer-badge" id="modal-viewer-badge"></span>
      </div>
      <div class="modal-bar-right">
        <button class="modal-action-btn" id="btn-retry" onclick="retryViewer()" title="Retry">
          <i class="fa-solid fa-rotate-right"></i>
        </button>
        <button class="btn-close" onclick="closeModal()" aria-label="Close">
          <i class="fa-solid fa-xmark"></i>
        </button>
      </div>
    </div>
    <div class="viewer-loading" id="viewer-loading">
      <div class="viewer-spinner"></div>
      <p id="viewer-loading-msg">Loading document…</p>
      <p class="viewer-loading-sub" id="viewer-sub-msg">This may take a moment</p>
    </div>
    <div class="viewer-error" id="viewer-error" style="display:none;">
      <div class="viewer-error-icon"><i class="fa-solid fa-triangle-exclamation"></i></div>
      <p id="viewer-error-msg">Could not load document</p>
      <p class="viewer-error-sub" id="viewer-error-sub">The viewer could not render this file.</p>
      <div class="viewer-error-btns">
        <button class="btn btn-primary btn-sm" onclick="retryViewer()">
          <i class="fa-solid fa-rotate-right"></i> Retry
        </button>
      </div>
    </div>
    <iframe id="modal-frame" title="Document viewer"></iframe>
  </div>
</div>

<script>
(() => {
  'use strict';

  // ── Theme toggle (light/dark, persisted) ────────────────
  const root       = document.documentElement;
  const themeBtn   = document.getElementById('theme-toggle');
  const themeIcon  = document.getElementById('theme-icon');
  function syncThemeIcon(){
    const isDark = root.getAttribute('data-theme') === 'dark';
    themeIcon.className = isDark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
  }
  syncThemeIcon();
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      root.classList.add('theme-transitioning');
      themeIcon.style.transform = 'rotate(180deg) scale(0)';
      themeIcon.style.opacity = '0';
      setTimeout(() => {
        root.setAttribute('data-theme', next);
        try { localStorage.setItem('dd-theme', next); } catch (e) {}
        syncThemeIcon();
        themeIcon.style.transform = 'rotate(360deg) scale(1)';
        themeIcon.style.opacity = '1';
        setTimeout(() => {
          themeIcon.style.transform = '';
          root.classList.remove('theme-transitioning');
        }, 400);
      }, 150);
    });
  }

  // ── Password visibility toggle ──────────────────────────
  const pwInput = document.getElementById('pw-input');
  const eyeBtn  = document.getElementById('eye-btn');
  const eyeIcon = document.getElementById('eye-icon');
  if (eyeBtn && pwInput) {
    eyeBtn.addEventListener('click', () => {
      const show = pwInput.type === 'password';
      pwInput.type = show ? 'text' : 'password';
      eyeIcon.className = show ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
    });
  }

  // ── Login form: disable button + spinner while submitting ─
  const loginForm = document.getElementById('login-form');
  const loginBtn  = document.getElementById('login-btn');
  if (loginForm && loginBtn) {
    loginForm.addEventListener('submit', () => {
      loginBtn.disabled = true;
      loginBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying…';
    });
  }

  // ── Search form: client-side length guard + loading state ─
  const searchForm  = document.getElementById('search-form');
  const searchInput = document.getElementById('search-input');
  const searchBtn   = document.getElementById('search-btn');
  if (searchForm) {
    searchForm.addEventListener('submit', (e) => {
      const val = (searchInput.value || '').trim();
      if (val.length > 0 && val.length < 3) {
        e.preventDefault();
        searchInput.focus();
        searchInput.style.borderColor = 'var(--danger)';
        setTimeout(() => { searchInput.style.borderColor = ''; }, 1200);
        return;
      }
      searchBtn.disabled = true;
      searchBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><span>Searching…</span>';
    });
  }

  // ── Document viewer modal logic ─────────────────────────
  const modal        = document.getElementById('modal');
  const modalFrame    = document.getElementById('modal-frame');
  const modalName     = document.getElementById('modal-filename');
  const modalIcon     = document.getElementById('modal-icon');
  const modalDot      = document.getElementById('modal-file-dot');
  const modalBadge    = document.getElementById('modal-viewer-badge');
  const viewerLoading = document.getElementById('viewer-loading');
  const viewerError   = document.getElementById('viewer-error');
  const loadingMsg    = document.getElementById('viewer-loading-msg');
  const loadingSub    = document.getElementById('viewer-sub-msg');
  const errorSub      = document.getElementById('viewer-error-sub');

  let _rawUrl = '', _vtype = '', _attempt = 0, _aborted = false, _strategies = [];
  let _timer = null, _pollTimer = null;

  const TIMEOUT_MS = 9000;
  const MAX_RETRIES = 4;

  const typeVisual = {
    pdf:{icon:'fa-file-pdf',color:'#F87171'}, doc:{icon:'fa-file-word',color:'#60A5FA'},
    docx:{icon:'fa-file-word',color:'#60A5FA'}, odt:{icon:'fa-file-word',color:'#60A5FA'},
    xls:{icon:'fa-file-excel',color:'#34D399'}, xlsx:{icon:'fa-file-excel',color:'#34D399'},
    ods:{icon:'fa-file-excel',color:'#34D399'}, ppt:{icon:'fa-file-powerpoint',color:'#FB923C'},
    pptx:{icon:'fa-file-powerpoint',color:'#FB923C'}, odp:{icon:'fa-file-powerpoint',color:'#FB923C'},
  };

  function extOf(name){ return (name.split('.').pop() || '').toLowerCase(); }

  function hasLikelyLocalPdfViewer(){
    const ua = navigator.userAgent || '';
    const isInAppWebview = /FBAN|FBAV|Instagram|Line\/|MicroMessenger|; ?wv\)/i.test(ua);
    if (isInAppWebview) return false;
    if (/Android/i.test(ua)) return false;
    return true;
  }

  function strategyList(vtype){
    if (vtype === 'pdf') {
      return hasLikelyLocalPdfViewer()
        ? ['direct','google','google','office']
        : ['google','office','google'];
    }
    if (vtype === 'google') return ['google','office','google'];
    if (vtype === 'office') return ['office','office'];
    return ['direct'];
  }

  function buildViewerUrl(rawUrl, strategy){
    if (strategy === 'google') return 'https://docs.google.com/viewer?embedded=true&url=' + encodeURIComponent(rawUrl);
    if (strategy === 'office') return 'https://view.officeapps.live.com/op/embed.aspx?src=' + encodeURIComponent(rawUrl);
    return rawUrl;
  }

  function showLoading(msg, sub){
    viewerLoading.style.display = 'flex';
    viewerError.style.display   = 'none';
    modalFrame.style.opacity    = '0';
    modalFrame.style.pointerEvents = 'none';
    if (msg) loadingMsg.textContent = msg;
    if (sub) loadingSub.textContent = sub;
  }
  function showReady(){
    viewerLoading.style.display = 'none';
    viewerError.style.display   = 'none';
    modalFrame.style.opacity    = '1';
    modalFrame.style.pointerEvents = 'auto';
  }
  function showError(sub){
    viewerLoading.style.display = 'none';
    viewerError.style.display   = 'flex';
    modalFrame.style.opacity    = '0';
    modalFrame.style.pointerEvents = 'none';
    if (sub) errorSub.textContent = sub;
  }

  function verifyIframeContent(onSuccess, onFail){
    let checks = 0;
    const maxChecks = 6;
    clearInterval(_pollTimer);
    _pollTimer = setInterval(() => {
      if (_aborted) { clearInterval(_pollTimer); return; }
      checks++;
      const rect = modalFrame.getBoundingClientRect();
      const hasSize = rect.width > 50 && rect.height > 100;
      if (hasSize) { clearInterval(_pollTimer); onSuccess(); }
      else if (checks >= maxChecks) { clearInterval(_pollTimer); onFail(); }
    }, 500);
  }

  function loadAttempt(){
    if (_aborted) return;
    clearTimeout(_timer);
    clearInterval(_pollTimer);

    if (_attempt >= MAX_RETRIES && _vtype !== 'none') {
      showError('Unable to load a preview after several attempts.');
      return;
    }

    const strategy = _strategies[_attempt] || _strategies[_strategies.length - 1];
    const url = buildViewerUrl(_rawUrl, strategy);

    if (_attempt === 0) {
      const sub = (strategy === 'google' && _vtype === 'pdf')
        ? 'No local PDF viewer detected — opening in Google Docs…'
        : 'Please wait…';
      showLoading('Loading document…', sub);
    }
    else {
      const isOfficeFallback = strategy === 'office' && (_vtype === 'google' || _vtype === 'pdf');
      const isPdfFallback    = strategy === 'google' && _vtype === 'pdf';
      const sub = isOfficeFallback ? 'Trying Microsoft Office viewer…'
                : isPdfFallback    ? 'Trying Google Docs viewer…'
                : 'Attempt ' + (_attempt + 1) + ' — please wait…';
      showLoading('Retrying…', sub);
    }

    modalFrame.removeEventListener('load', _onLoad);
    modalFrame.removeEventListener('error', _onError);
    modalFrame.src = 'about:blank';

    setTimeout(() => {
      if (_aborted) return;
      modalFrame.addEventListener('load', _onLoad, { once:true });
      modalFrame.addEventListener('error', _onError, { once:true });
      modalFrame.src = url;

      _timer = setTimeout(() => {
        if (_aborted) return;
        _attempt++;
        loadAttempt();
      }, TIMEOUT_MS);
    }, 120);
  }

  function _onLoad(){
    if (_aborted) return;
    clearTimeout(_timer);
    setTimeout(() => {
      if (_aborted) return;
      verifyIframeContent(
        () => { if (!_aborted) showReady(); },
        () => { if (!_aborted) { _attempt++; loadAttempt(); } }
      );
    }, 800);
  }

  function _onError(){
    if (_aborted) return;
    clearTimeout(_timer);
    clearInterval(_pollTimer);
    _attempt++;
    loadAttempt();
  }

  window.handleFileClick = function(el){
    const isModal = el.dataset.modal === '1';
    const title  = el.dataset.modalTitle || 'Document';
    const rawUrl = el.dataset.rawUrl || el.dataset.href;
    const vtype  = el.dataset.viewerType || 'none';

    if (!isModal) { window.open(el.dataset.href, '_blank', 'noopener,noreferrer'); return; }

    const ext = extOf(title);
    const vis = typeVisual[ext] || { icon:'fa-file', color:'#94A3B8' };

    modalName.textContent = title;
    modalIcon.className   = 'fa-solid ' + vis.icon;
    modalIcon.style.color = vis.color;
    modalDot.style.background = vis.color;

    modal.classList.add('open');
    document.body.style.overflow = 'hidden';

    _rawUrl = rawUrl;
    _vtype  = vtype;
    _attempt = 0;
    _aborted = false;
    _strategies = strategyList(vtype);

    const firstStrategy = _strategies[0];
    const isGoogle = firstStrategy === 'google';
    const isOffice = firstStrategy === 'office';
    modalBadge.textContent = isGoogle ? 'Google Docs' : isOffice ? 'Microsoft Office' : '';
    modalBadge.style.cssText = isGoogle
      ? 'background:#4285F4;color:#fff;border-color:#4285F4;display:inline;'
      : isOffice
      ? 'background:#0078D4;color:#fff;border-color:#0078D4;display:inline;'
      : 'display:none;';

    showLoading('Loading document…', 'Please wait…');
    loadAttempt();
  };

  window.retryViewer = function(){
    if (!_rawUrl) return;
    _attempt = 0;
    _aborted = false;
    showLoading('Retrying…', 'Starting fresh…');
    loadAttempt();
  };

  window.closeModal = function(){
    _aborted = true;
    clearTimeout(_timer);
    clearInterval(_pollTimer);
    modal.classList.remove('open');
    modalFrame.removeEventListener('load', _onLoad);
    modalFrame.removeEventListener('error', _onError);
    modalFrame.src = 'about:blank';
    showLoading('Loading document…', 'Please wait…');
    _rawUrl = '';
    document.body.style.overflow = '';
  };

  modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('open')) closeModal();
  });
})();
</script>
</body>
</html>
