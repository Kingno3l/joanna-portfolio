<?php
/**
 * Joanna Olayemi Stephen Portfolio - Form Submission Endpoint
 * 
 * Features:
 * 1. Cloudflare Turnstile Bot Verification (using secret key)
 * 2. Honeypot anti-spam defense
 * 3. Server-side sanitization & validation
 * 4. MySQL database logging (table: contact_messages)
 * 5. Admin email notification to contactme@joannastephen.com
 * 6. Automated confirmation autoresponder email to submitter
 * 7. Clean JSON API response
 */

// Set strict error reporting & JSON response header
error_reporting(E_ALL);
ini_set('display_errors', '0');
header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// Load configuration securely (checks multiple safe locations outside or within web root)
$configCandidates = [
    __DIR__ . '/config.php',
    __DIR__ . '/../joanna_config.php',
    __DIR__ . '/../config.php',
    __DIR__ . '/../../joanna_config.php',
    __DIR__ . '/../../config.php'
];

$configLoaded = false;
foreach ($configCandidates as $candidate) {
    if (file_exists($candidate)) {
        require_once $candidate;
        $configLoaded = true;
        break;
    }
}

if (!$configLoaded) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Server configuration file not found.'
    ]);
    exit;
}

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'error' => 'Method Not Allowed. Only POST requests are accepted.'
    ]);
    exit;
}

// Support both standard POST (FormData / urlencoded) and JSON payload
$input = $_POST;
$rawInput = file_get_contents('php://input');
if (empty($input) && !empty($rawInput)) {
    $jsonData = json_decode($rawInput, true);
    if (is_array($jsonData)) {
        $input = $jsonData;
    }
}

// ----------------------------------------------------
// 1. HONEYPOT SPAM PROTECTION
// ----------------------------------------------------
$honeypot = isset($input['security_hp_token']) ? trim((string)$input['security_hp_token']) : '';
if (!empty($honeypot)) {
    // Silently reject spambots without processing
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'message' => 'Thank you! Your message has been received.'
    ]);
    exit;
}

// ----------------------------------------------------
// 2. CLOUDFLARE TURNSTILE VERIFICATION
// ----------------------------------------------------
$turnstileResponse = isset($input['cf-turnstile-response']) 
    ? trim((string)$input['cf-turnstile-response']) 
    : (isset($input['turnstile_token']) ? trim((string)$input['turnstile_token']) : '');

$remoteIp = $_SERVER['REMOTE_ADDR'] ?? '';
$turnstileVerified = false;

if (empty($turnstileResponse)) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => 'Please complete the Cloudflare security verification before submitting.'
    ]);
    exit;
}

// Verify token with Cloudflare API
$cfVerifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
$postData = http_build_query([
    'secret'   => TURNSTILE_SECRET_KEY,
    'response' => $turnstileResponse,
    'remoteip' => $remoteIp
]);

$verificationSuccess = false;

if (function_exists('curl_init')) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $cfVerifyUrl);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $cfRawResponse = curl_exec($ch);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($cfRawResponse !== false) {
        $cfResult = json_decode($cfRawResponse, true);
        if (!empty($cfResult['success'])) {
            $verificationSuccess = true;
            $turnstileVerified = true;
        }
    }
}

// Fallback to file_get_contents if curl wasn't available or failed
if (!$verificationSuccess && ini_get('allow_url_fopen')) {
    $opts = [
        'http' => [
            'method'  => 'POST',
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'content' => $postData,
            'timeout' => 10
        ]
    ];
    $context = stream_context_create($opts);
    $cfRawResponse = @file_get_contents($cfVerifyUrl, false, $context);
    if ($cfRawResponse !== false) {
        $cfResult = json_decode($cfRawResponse, true);
        if (!empty($cfResult['success'])) {
            $verificationSuccess = true;
            $turnstileVerified = true;
        }
    }
}

// Check if running in local environment
$isLocalhost = in_array($remoteIp, ['127.0.0.1', '::1', 'localhost']) || 
               in_array($_SERVER['SERVER_NAME'] ?? '', ['localhost', '127.0.0.1']);

// If Turnstile verification failed, block the bot
if (!$verificationSuccess) {
    $cfErrors = $cfResult['error-codes'] ?? [];
    // Allow graceful fallback for local development if Cloudflare reports hostname mismatch
    if ($isLocalhost && (in_array('hostname-mismatch', $cfErrors) || in_array('invalid-input-response', $cfErrors))) {
        $verificationSuccess = true;
        $turnstileVerified = true;
        error_log('Notice: Cloudflare Turnstile local dev bypass triggered for ' . implode(',', $cfErrors));
    } else {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'error' => 'Bot verification failed. Please complete the security check and try again.'
        ]);
        exit;
    }
}

// ----------------------------------------------------
// 3. INPUT SANITIZATION & VALIDATION
// ----------------------------------------------------
$fullName = isset($input['fullName']) ? trim((string)$input['fullName']) : '';
$email    = isset($input['email']) ? trim((string)$input['email']) : '';
$phone    = isset($input['phone']) ? trim((string)$input['phone']) : '';
$reason   = isset($input['reason']) ? trim((string)$input['reason']) : '';
$message  = isset($input['message']) ? trim((string)$input['message']) : '';

// Sanitize inputs
$fullName = preg_replace('/[\r\n\t\0]/', ' ', $fullName);
$fullName = preg_replace('/\s+/', ' ', $fullName);

$email = filter_var($email, FILTER_SANITIZE_EMAIL);

$phone = preg_replace('/[^\d\s\+\-\(\)\.]/', '', $phone);
$phone = trim($phone);

$reason = preg_replace('/[\r\n\t\0]/', ' ', $reason);
$reason = trim($reason);

$message = str_replace(["\r\n", "\r"], "\n", $message);
$message = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $message);

// Validation rules
$allowedReasons = [
    'Publications',
    'Conference Collaboration',
    'Educational Innovation',
    'Classroom Practice',
    'Consulting',
    'Program Leadership',
    'Professional Services',
    'Others'
];

if (empty($fullName) || mb_strlen($fullName) < 2 || mb_strlen($fullName) > 80) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Please provide a valid full name (2 to 80 characters).']);
    exit;
}

if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Please provide a valid email address.']);
    exit;
}

if (!empty($phone) && mb_strlen($phone) > 30) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Phone number exceeds maximum length.']);
    exit;
}

if (empty($reason) || !in_array($reason, $allowedReasons, true)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Please select a valid Reason of Contact.']);
    exit;
}

if (empty($message) || mb_strlen($message) < 5) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Please enter a message with at least 5 characters.']);
    exit;
}

if (mb_strlen($message) > 3000) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Message exceeds 3,000 characters limit.']);
    exit;
}

$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// ----------------------------------------------------
// 4. DATABASE LOGGING (MySQL / PDO)
// ----------------------------------------------------
$dbInserted = false;
$messageId = null;
$pdo = null;

try {
    $dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', DB_HOST, DB_PORT, DB_NAME);
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);

    // Ensure table exists
    $createTableSql = "
        CREATE TABLE IF NOT EXISTS contact_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(100) NOT NULL,
            email VARCHAR(120) NOT NULL,
            phone VARCHAR(30) NULL,
            reason VARCHAR(100) NOT NULL,
            message TEXT NOT NULL,
            ip_address VARCHAR(45) NULL,
            user_agent TEXT NULL,
            turnstile_verified TINYINT(1) DEFAULT 0,
            notification_sent TINYINT(1) DEFAULT 0,
            autoresponder_sent TINYINT(1) DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ";
    $pdo->exec($createTableSql);

    $stmt = $pdo->prepare("
        INSERT INTO contact_messages 
        (full_name, email, phone, reason, message, ip_address, user_agent, turnstile_verified, notification_sent, autoresponder_sent, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, NOW())
    ");
    $stmt->execute([
        $fullName,
        $email,
        $phone ?: null,
        $reason,
        $message,
        $remoteIp,
        substr($userAgent, 0, 500),
        $turnstileVerified ? 1 : 0
    ]);
    $messageId = $pdo->lastInsertId();
    $dbInserted = true;
} catch (Exception $e) {
    // Log database error silently to error log without disclosing credentials
    error_log('Database error in contact.php: ' . $e->getMessage());
}

// ----------------------------------------------------
// 5. HELPER: SEND EMAIL FUNCTION (SMTP or mail())
// ----------------------------------------------------
function sendSmtpMail($toEmail, $subject, $htmlBody, $replyToEmail = null, $replyToName = null) {
    if (!defined('SMTP_HOST') || !defined('SMTP_USER') || !defined('SMTP_PASS') || empty(SMTP_PASS)) {
        return false;
    }

    $host = SMTP_HOST;
    $port = SMTP_PORT;
    $user = SMTP_USER;
    $pass = SMTP_PASS;
    $secure = SMTP_SECURE;

    $prefix = ($secure === 'ssl') ? 'ssl://' : '';
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true
        ]
    ]);
    $socket = @stream_socket_client($prefix . $host . ':' . $port, $errno, $errstr, 12, STREAM_CLIENT_CONNECT, $context);
    if (!$socket) {
        error_log("SMTP connection failed to {$host}:{$port} - $errstr ($errno)");
        return false;
    }

    $read = function() use ($socket) {
        $data = '';
        while ($str = fgets($socket, 515)) {
            $data .= $str;
            if (substr($str, 3, 1) === ' ') break;
        }
        return $data;
    };

    $write = function($cmd) use ($socket) {
        fputs($socket, $cmd . "\r\n");
    };

    $read();
    $write("EHLO " . ($_SERVER['SERVER_NAME'] ?? 'localhost'));
    $read();

    if ($secure === 'tls') {
        $write("STARTTLS");
        $read();
        stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        $write("EHLO " . ($_SERVER['SERVER_NAME'] ?? 'localhost'));
        $read();
    }

    $write("AUTH LOGIN");
    $read();
    $write(base64_encode($user));
    $read();
    $write(base64_encode($pass));
    $authRes = $read();
    if (substr($authRes, 0, 3) !== '235') {
        error_log("SMTP Auth failed: " . $authRes);
        $write("QUIT");
        fclose($socket);
        return false;
    }

    $fromMail = defined('SENDER_EMAIL') ? SENDER_EMAIL : (defined('ADMIN_EMAIL') ? ADMIN_EMAIL : 'noreply@joannastephen.com');
    $fromName = defined('SITE_NAME') ? SITE_NAME : (defined('ADMIN_NAME') ? ADMIN_NAME : 'Joanna Olayemi Stephen');

    $write("MAIL FROM: <" . $fromMail . ">");
    $read();
    $write("RCPT TO: <" . $toEmail . ">");
    $read();
    $write("DATA");
    $read();

    $headers = [
        "MIME-Version: 1.0",
        "Content-Type: text/html; charset=UTF-8",
        "From: " . $fromName . " <" . $fromMail . ">",
        "To: <" . $toEmail . ">",
        "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=",
        "Date: " . date('r'),
        "X-Mailer: JoannaStephen-Mailer/1.0"
    ];
    if ($replyToEmail) {
        $headers[] = "Reply-To: " . ($replyToName ?: $replyToEmail) . " <" . $replyToEmail . ">";
    }

    $payload = implode("\r\n", $headers) . "\r\n\r\n" . $htmlBody . "\r\n.\r\n";
    $write($payload);
    $res = $read();

    $write("QUIT");
    fclose($socket);

    return substr($res, 0, 3) === '250';
}

function sendHtmlEmail($toEmail, $toName, $subject, $htmlBody, $replyToEmail = null, $replyToName = null) {
    $sent = false;

    // 1. Try authenticated SMTP if configured
    if (defined('SMTP_ENABLED') && SMTP_ENABLED && defined('SMTP_PASS') && !empty(SMTP_PASS)) {
        $sent = sendSmtpMail($toEmail, $subject, $htmlBody, $replyToEmail, $replyToName);
    }

    // 2. Fallback to native PHP mail()
    if (!$sent) {
        $fromEmail = defined('SENDER_EMAIL') ? SENDER_EMAIL : (defined('ADMIN_EMAIL') ? ADMIN_EMAIL : 'noreply@joannastephen.com');
        $fromName  = defined('SITE_NAME') ? SITE_NAME : (defined('ADMIN_NAME') ? ADMIN_NAME : 'Joanna Olayemi Stephen');

        $headers  = "MIME-Version: 1.0\r\n";
        $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
        $headers .= "From: {$fromName} <{$fromEmail}>\r\n";

        if ($replyToEmail) {
            $rName = $replyToName ? $replyToName : $replyToEmail;
            $headers .= "Reply-To: {$rName} <{$replyToEmail}>\r\n";
        } else {
            $headers .= "Reply-To: {$fromName} <{$fromEmail}>\r\n";
        }

        $headers .= "X-Mailer: PHP/" . phpversion() . "\r\n";
        $headers .= "X-Priority: 1 (Highest)\r\n";

        $sent = @mail($toEmail, $subject, $htmlBody, $headers);
    }

    // 3. Log email dispatch for auditing
    $logLine = sprintf(
        "[%s] Recipient: %s (%s) | Subject: %s | Status: %s\n",
        date('Y-m-d H:i:s'),
        $toEmail,
        $toName,
        $subject,
        $sent ? 'SENT' : 'LOGGED (local environment)'
    );
    @file_put_contents(__DIR__ . '/emails.log', $logLine, FILE_APPEND | LOCK_EX);

    return $sent;
}

// ----------------------------------------------------
// 6. ADMIN NOTIFICATION EMAIL TEMPLATE
// ----------------------------------------------------
$adminSubject = "[New Inquiry - {$reason}] from {$fullName}";
$safeFullName = htmlspecialchars($fullName, ENT_QUOTES, 'UTF-8');
$safeEmail    = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
$safePhone    = htmlspecialchars($phone ?: 'Not provided', ENT_QUOTES, 'UTF-8');
$safeReason   = htmlspecialchars($reason, ENT_QUOTES, 'UTF-8');
$safeMessage  = nl2br(htmlspecialchars($message, ENT_QUOTES, 'UTF-8'));
$currentDate  = date('F j, Y, g:i a T');

$adminHtml = <<<HTML
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>{$adminSubject}</title>
<style>
  body { margin: 0; padding: 24px; background: #f4f6f8; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #142f42; }
  .card { max-width: 620px; margin: 0 auto; background: #ffffff; border-radius: 16px; overflow: hidden; border: 1px solid #e1e7ec; box-shadow: 0 10px 30px rgba(20,47,66,.06); }
  .header { background: #124f3c; color: #ffffff; padding: 28px 32px; }
  .header h2 { margin: 0 0 6px; font-size: 20px; font-weight: 700; }
  .header p { margin: 0; color: #a3d9c3; font-size: 13px; letter-spacing: 0.5px; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 50px; background: #e9f4ee; color: #124f3c; font-weight: 700; font-size: 12px; }
  .content { padding: 32px; }
  .info-table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
  .info-table td { padding: 10px 0; border-bottom: 1px solid #edf2f5; font-size: 14px; }
  .info-table td.label { width: 35%; color: #617783; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.6px; }
  .info-table td.val { color: #142f42; font-weight: 600; }
  .message-box { background: #fbfaf5; border: 1px solid #dbe6e1; border-left: 4px solid #2f8062; border-radius: 8px; padding: 18px 20px; margin-top: 20px; line-height: 1.65; font-size: 14px; }
  .btn-reply { display: inline-block; background: #2f8062; color: #ffffff !important; text-decoration: none; padding: 12px 26px; border-radius: 10px; font-weight: 700; font-size: 14px; margin-top: 24px; }
  .footer { background: #fbfaf5; padding: 18px 32px; border-top: 1px solid #e1e7ec; font-size: 12px; color: #8c9da8; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <p>JOANNA OLAYEMI STEPHEN · PORTFOLIO INQUIRY</p>
    <h2>New Verified Message Received</h2>
  </div>
  <div class="content">
    <table class="info-table">
      <tr>
        <td class="label">Full Name</td>
        <td class="val">{$safeFullName}</td>
      </tr>
      <tr>
        <td class="label">Email Address</td>
        <td class="val"><a href="mailto:{$safeEmail}" style="color:#2f8062;text-decoration:none;">{$safeEmail}</a></td>
      </tr>
      <tr>
        <td class="label">Phone Number</td>
        <td class="val">{$safePhone}</td>
      </tr>
      <tr>
        <td class="label">Reason of Contact</td>
        <td class="val"><span class="badge">{$safeReason}</span></td>
      </tr>
      <tr>
        <td class="label">Submission Time</td>
        <td class="val">{$currentDate}</td>
      </tr>
      <tr>
        <td class="label">Security Verification</td>
        <td class="val" style="color:#124f3c;">✓ Cloudflare Turnstile Verified</td>
      </tr>
    </table>

    <div style="font-size:12px;font-weight:700;color:#617783;text-transform:uppercase;letter-spacing:0.8px;margin-top:16px;">Message Content</div>
    <div class="message-box">
      {$safeMessage}
    </div>

    <div style="text-align:center;">
      <a href="mailto:{$safeEmail}?subject=Re:%20[{$safeReason}]%20Inquiry%20from%20{$safeFullName}" class="btn-reply">Reply Directly to {$safeFullName} →</a>
    </div>
  </div>
  <div class="footer">
    Sent securely via portfolio contact form to <strong>contactme@joannastephen.com</strong>.<br>
    IP: {$remoteIp} · Bot Verification: Passed
  </div>
</div>
</body>
</html>
HTML;

// ----------------------------------------------------
// 7. USER CONFIRMATION AUTORESPONDER TEMPLATE
// ----------------------------------------------------
$userSubject = "Thank you for contacting Joanna Olayemi Stephen";

$userHtml = <<<HTML
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>{$userSubject}</title>
<style>
  body { margin: 0; padding: 24px; background: #fbfaf5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #142f42; }
  .card { max-width: 620px; margin: 0 auto; background: #ffffff; border-radius: 18px; overflow: hidden; border: 1px solid #dbe6e1; box-shadow: 0 16px 40px rgba(20,47,66,.07); }
  .header { background: #124f3c; color: #ffffff; padding: 36px 36px 30px; text-align: center; }
  .brandmark { width: 46px; height: 46px; border-radius: 50%; background: #e9f4ee; color: #124f3c; font-size: 22px; line-height: 46px; margin: 0 auto 12px; font-weight: 800; display: block; }
  .header h1 { margin: 0 0 6px; font-size: 22px; font-weight: 800; color: #ffffff; letter-spacing: -0.2px; }
  .header p { margin: 0; color: #b7e3d1; font-size: 13px; font-weight: 500; }
  .content { padding: 36px; line-height: 1.68; font-size: 15px; color: #233e50; }
  .greeting { font-size: 17px; font-weight: 700; color: #142f42; margin-bottom: 16px; }
  .recap-box { background: #f9fbf9; border: 1px solid #dbe6e1; border-radius: 12px; padding: 20px; margin: 24px 0; }
  .recap-title { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: #2f8062; margin-bottom: 10px; }
  .recap-item { margin-bottom: 8px; font-size: 13.5px; }
  .recap-label { font-weight: 600; color: #617783; }
  .signature { margin-top: 32px; padding-top: 24px; border-top: 1px solid #edf2f5; }
  .sig-name { font-weight: 800; font-size: 16px; color: #142f42; }
  .sig-title { font-size: 13px; color: #617783; margin: 2px 0 10px; }
  .sig-links a { color: #2f8062; text-decoration: none; font-weight: 600; font-size: 13px; margin-right: 12px; }
  .footer { background: #f4f6f8; padding: 20px 36px; text-align: center; font-size: 12px; color: #8c9da8; border-top: 1px solid #e1e7ec; }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="brandmark">J</div>
    <h1>Joanna Olayemi Stephen</h1>
    <p>Educator · Researcher · Educational Innovator · Winston-Salem, NC</p>
  </div>
  <div class="content">
    <div class="greeting">Dear {$safeFullName},</div>
    <p>
      Thank you for reaching out regarding <strong>{$safeReason}</strong>. I have successfully received your inquiry through my portfolio website, and it has been directed to my primary webmail at <strong style="color:#124f3c;">contactme@joannastephen.com</strong>.
    </p>
    <p>
      Whether you reached out for academic collaboration, conference engagement, educational consulting, or professional inquiry, I appreciate your interest in my work. I will review your message carefully and get back to you shortly.
    </p>

    <div class="recap-box">
      <div class="recap-title">Summary of Your Message</div>
      <div class="recap-item"><span class="recap-label">Reason:</span> <strong>{$safeReason}</strong></div>
      <div class="recap-item"><span class="recap-label">Email:</span> {$safeEmail}</div>
      {$safePhoneHtml}
      <div class="recap-item" style="margin-top:12px;"><span class="recap-label">Message:</span><br>
        <span style="color:#3e5564;font-style:italic;">{$safeMessage}</span>
      </div>
    </div>

    <div class="signature">
      <div class="sig-name">Joanna Olayemi Stephen</div>
      <div class="sig-title">
        Educator · Researcher · Educational Innovator<br>
        Founder, Exceptional Roots Learning<br>
        Winston-Salem, North Carolina, USA
      </div>
      <div class="sig-links">
        <a href="mailto:contactme@joannastephen.com">contactme@joannastephen.com</a>
        <a href="https://www.linkedin.com/in/joanna-stephen-976418128">LinkedIn ↗</a>
        <a href="https://exceptionalrootslearning.com">Exceptional Roots ↗</a>
      </div>
    </div>
  </div>
  <div class="footer">
    This is an automated confirmation that your submission was received securely.<br>
    © 2026 Joanna Olayemi Stephen. All rights reserved.
  </div>
</div>
</body>
</html>
HTML;

$safePhoneHtml = $phone ? "<div class=\"recap-item\"><span class=\"recap-label\">Phone:</span> {$safePhone}</div>" : "";
$userHtml = str_replace('{$safePhoneHtml}', $safePhoneHtml, $userHtml);

// ----------------------------------------------------
// 8. DISPATCH EMAILS & UPDATE DB STATUS
// ----------------------------------------------------
$adminRecipients = defined('ADMIN_EMAILS') && !empty(ADMIN_EMAILS) 
    ? array_map('trim', explode(',', ADMIN_EMAILS)) 
    : [ADMIN_EMAIL];

$senderEmail = defined('SENDER_EMAIL') ? SENDER_EMAIL : ADMIN_EMAIL;
$senderName  = defined('ADMIN_NAME') ? ADMIN_NAME : SITE_NAME;

$adminSent = true;
foreach ($adminRecipients as $recip) {
    if (!empty($recip) && filter_var($recip, FILTER_VALIDATE_EMAIL)) {
        $s = sendHtmlEmail(
            $recip,
            ADMIN_NAME,
            $adminSubject,
            $adminHtml,
            $email,
            $fullName
        );
        if (!$s) $adminSent = false;
    }
}

$userSent = sendHtmlEmail(
    $email,
    $fullName,
    $userSubject,
    $userHtml,
    $senderEmail,
    $senderName
);

// Update DB statuses if PDO connection was established
if ($dbInserted && $messageId && $pdo) {
    try {
        $updateStmt = $pdo->prepare("
            UPDATE contact_messages 
            SET notification_sent = ?, autoresponder_sent = ? 
            WHERE id = ?
        ");
        $updateStmt->execute([
            $adminSent ? 1 : 0,
            $userSent ? 1 : 0,
            $messageId
        ]);
    } catch (Exception $e) {
        error_log('Failed to update email sent status: ' . $e->getMessage());
    }
}

// ----------------------------------------------------
// 9. RETURN JSON RESPONSE
// ----------------------------------------------------
http_response_code(200);
echo json_encode([
    'success' => true,
    'message' => "Thank you, {$fullName}! Your message has been sent successfully to Joanna. A confirmation has also been dispatched to {$email}.",
    'details' => [
        'full_name' => $fullName,
        'email' => $email,
        'reason' => $reason,
        'turnstile_verified' => true,
        'db_saved' => $dbInserted,
        'notification_sent' => $adminSent,
        'autoresponder_sent' => $userSent
    ]
]);
exit;
