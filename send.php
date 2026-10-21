<?php
/**
 * RESET — Generic form mailer.
 *
 * Drop this file into the SAME folder as index.html when you upload the
 * built site to Hostinger (or any PHP-capable host). It accepts POSTs from
 * every form on the site and forwards the data to the team by email.
 *
 * BEFORE GOING LIVE:
 *   1. Set RESET_MAIL_TO in the PHP host environment to your real team inbox.
 *   2. Set RESET_MAIL_FROM to an address on the same domain as the host (avoids the
 *      message landing in spam — Hostinger's PHP mail headers need this).
 *   3. Optional: change $SUBJECT_PREFIX to suit your branding.
 *
 * SECURITY:
 *   - The honeypot field "website_hp" is silently dropped (bots love it).
 *   - All values are sanitized before they go into the email body.
 *   - Header fields (From, Reply-To) reject any string containing \r or \n
 *     so a poisoned email field can't smuggle in extra headers.
 *   - Submissions are rate-limited per IP (10 per hour by default) using a
 *     locked flat-file counter in /tmp. The PHP host must provide a writable
 *     temporary directory; otherwise delivery reports a temporary failure.
 */

// ─── CONFIGURATION ──────────────────────────────────────────────────────────
$TO              = trim(getenv('RESET_MAIL_TO') ?: '');
$FROM            = trim(getenv('RESET_MAIL_FROM') ?: '');
$SUBJECT_PREFIX  = 'RESET — ';
$RATE_LIMIT      = 10;                          // submissions per IP per hour
$RATE_WINDOW     = 3600;                        // seconds

// ─── BOILERPLATE ────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=UTF-8');

function respond($status, $payload) {
    http_response_code($status);
    echo json_encode($payload);
    exit;
}

// Reject non-POST requests so a stray GET doesn't trigger an empty mail.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(405, ['ok' => false, 'error' => 'Method not allowed']);
}

// ─── HONEYPOT ───────────────────────────────────────────────────────────────
// Real visitors never see / fill the hidden "website_hp" field. If it has
// a value, treat the submitter as a bot — return success silently so the
// bot believes it succeeded and doesn't retry.
if (!empty($_POST['website_hp'])) {
    respond(200, ['ok' => true]);
}

// Fail safely until a real recipient and sender are configured. Never send
// private intake information to the example addresses shipped with a template.
if (!filter_var($TO, FILTER_VALIDATE_EMAIL) || !filter_var($FROM, FILTER_VALIDATE_EMAIL)) {
    respond(503, ['ok' => false, 'error' => 'Email delivery is not configured. Please contact the team directly.']);
}

// Reject malformed fields before constructing headers or touching the mailer.
if (!isset($_POST['form_type']) || !is_string($_POST['form_type']) || strlen($_POST['form_type']) > 100) {
    respond(400, ['ok' => false, 'error' => 'A valid form type is required.']);
}
if (isset($_POST['email']) && (!is_string($_POST['email']) ||
    (trim($_POST['email']) !== '' && !filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL)))) {
    respond(400, ['ok' => false, 'error' => 'Enter a valid email address.']);
}
if (count($_POST) > 100 || strlen(json_encode($_POST)) > 32000) {
    respond(413, ['ok' => false, 'error' => 'Submission is too large.']);
}

// ─── RATE LIMIT (atomic, per source IP) ─────────────────────────────────────
// Forwarded headers are supplied by callers unless a trusted proxy validates
// them. The source address avoids letting callers reset their own quota.
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$file = sys_get_temp_dir() . '/reset_send_rate.json';
$handle = @fopen($file, 'c+');
if (!$handle || !flock($handle, LOCK_EX)) {
    if ($handle) fclose($handle);
    respond(503, ['ok' => false, 'error' => 'Email delivery is temporarily unavailable. Please try again later.']);
}
try {
    $now  = time();
    $data = json_decode(stream_get_contents($handle), true);
    if (!is_array($data)) $data = [];
    // Prune entries older than the window.
    foreach ($data as $entryIp => $entry) {
        if (!is_array($entry) || ($entry['first'] ?? 0) + $RATE_WINDOW < $now) {
            unset($data[$entryIp]);
        }
    }
    if (!isset($data[$ip])) {
        $data[$ip] = ['first' => $now, 'count' => 0];
    }
    if ($data[$ip]['count'] >= $RATE_LIMIT) {
        flock($handle, LOCK_UN);
        fclose($handle);
        $handle = null;
        respond(429, ['ok' => false, 'error' => 'Too many submissions. Try again later.']);
    }
    $data[$ip]['count'] += 1;
    $encoded = json_encode($data);
    if (!rewind($handle) || !@ftruncate($handle, 0) || @fwrite($handle, $encoded) !== strlen($encoded)) {
        respond(503, ['ok' => false, 'error' => 'Email delivery is temporarily unavailable.']);
    }
} finally {
    if (is_resource($handle)) {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}

// ─── EXTRACT + SANITIZE FIELDS ──────────────────────────────────────────────
// Every form on the site carries a hidden form_type marker so the team can
// tell at a glance which form was used.
$formType = isset($_POST['form_type']) ? (string) $_POST['form_type'] : 'unknown';
$formType = preg_replace('/[^A-Za-z0-9 _\-]/', '', $formType);
if ($formType === '') $formType = 'unknown';

// Build the email body — one "Field: value" line per submitted field. Arrays
// (checkbox groups, repeating fields) are joined with commas.
$lines = [];
foreach ($_POST as $key => $value) {
    if ($key === 'website_hp')  continue; // never leak the honeypot
    if ($key === 'form_type')   continue; // included in subject + header
    $cleanKey = preg_replace('/[^A-Za-z0-9 _\-]/', '', (string) $key);
    if ($cleanKey === '') continue;
    if (is_array($value)) {
        $clean = array_map(function ($v) {
            return is_string($v) ? trim($v) : '';
        }, $value);
        $value = implode(', ', array_filter($clean));
    } else {
        $value = trim((string) $value);
    }
    // Truncate absurdly long values so the email body stays sane.
    if (strlen($value) > 4000) $value = substr($value, 0, 4000) . '…';
    $lines[] = sprintf('%s: %s', $cleanKey, $value);
}

if (empty($lines)) {
    respond(400, ['ok' => false, 'error' => 'No form fields submitted.']);
}

// ─── BUILD EMAIL ────────────────────────────────────────────────────────────
$subject = $SUBJECT_PREFIX . $formType . ' submission';

$body  = "A new {$formType} submission landed on the RESET website.\n";
$body .= "Submitted at: " . date('Y-m-d H:i:s T') . "\n";
$body .= "Source IP: " . $ip . "\n";
$body .= "User-Agent: " . substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200) . "\n";
$body .= str_repeat('-', 60) . "\n\n";
$body .= implode("\n", $lines) . "\n";

// Headers — reject any value that tries to inject CRLF (poisoned email field
// could otherwise smuggle in BCC: lines).
function safe_header_value($value) {
    if (!is_string($value) || preg_match('/[\r\n]/', $value)) return '';
    return trim($value);
}
$replyTo = safe_header_value($_POST['email'] ?? $FROM);
if ($replyTo === '') $replyTo = $FROM;

$headers   = [];
$headers[] = 'From: ' . $FROM;
$headers[] = 'Reply-To: ' . $replyTo;
$headers[] = 'X-Mailer: PHP/' . phpversion();
$headers[] = 'Content-Type: text/plain; charset=UTF-8';

// ─── SEND ───────────────────────────────────────────────────────────────────
$sent = @mail($TO, $subject, $body, implode("\r\n", $headers));

if ($sent) {
    respond(200, ['ok' => true, 'form_type' => $formType]);
} else {
    // mail() can return false for many reasons (Hostinger SMTP misconfig,
    // /tmp full, blacklisted From). The submission is still captured in
    // the dashboard's localStorage on the visitor's browser, so this is
    // not a complete data loss.
    respond(500, ['ok' => false, 'error' => 'Mail server refused the message. Check the Hostinger PHP mail settings.']);
}
