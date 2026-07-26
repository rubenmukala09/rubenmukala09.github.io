<?php
/**
 * RESET — Generic form mailer.
 *
 * Drop this file into the SAME folder as index.html when you upload the
 * built site to Hostinger (or any PHP-capable host). It accepts POSTs from
 * every form on the site and forwards the data to the team by email.
 *
 * BEFORE GOING LIVE:
 *   1. Edit $TO below to your real team inbox.
 *   2. Edit $FROM to an address on the same domain as the host (avoids the
 *      message landing in spam — Hostinger's PHP mail headers need this).
 *   3. Optional: change $SUBJECT_PREFIX to suit your branding.
 *
 * SECURITY:
 *   - The honeypot field "website_hp" is silently dropped (bots love it).
 *   - All values are sanitized before they go into the email body.
 *   - Header fields (From, Reply-To) reject any string containing \r or \n
 *     so a poisoned email field can't smuggle in extra headers.
 *   - Submissions are rate-limited per IP (10 per hour by default) using a
 *     small flat-file counter in /tmp. Disable by deleting the rate-limit
 *     block if your host's /tmp isn't writeable.
 */

// ─── CONFIGURATION ──────────────────────────────────────────────────────────
$TO              = 'team@reset.org';            // ← change to your real inbox
$FROM            = 'noreply@reset.org';         // ← address on your domain
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

// ─── RATE LIMIT (best-effort, flat file) ────────────────────────────────────
// Tracks per-IP submission counts in /tmp/reset_send_rate.json. If the file
// system is read-only, the limit silently no-ops.
$ip   = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$ip   = preg_split('/,\s*/', $ip)[0]; // take first hop only
$file = sys_get_temp_dir() . '/reset_send_rate.json';
if (is_writable(dirname($file))) {
    $now  = time();
    $data = is_readable($file) ? json_decode(@file_get_contents($file), true) : [];
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
        respond(429, ['ok' => false, 'error' => 'Too many submissions. Try again later.']);
    }
    $data[$ip]['count'] += 1;
    @file_put_contents($file, json_encode($data), LOCK_EX);
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
    if (preg_match('/[\r\n]/', $value)) return '';
    return $value;
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
