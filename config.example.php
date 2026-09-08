<?php
/**
 * Joanna Olayemi Stephen Portfolio - Configuration Settings Template
 * 
 * Copy this file to config.php and configure your environment variables or credentials.
 * DO NOT commit config.php with real secret keys to public repositories.
 */

// Database Configuration
define('DB_HOST', getenv('DB_HOST') ?: '127.0.0.1');
define('DB_PORT', getenv('DB_PORT') ?: '3306');
define('DB_NAME', getenv('DB_NAME') ?: 'joanna_stephen');
define('DB_USER', getenv('DB_USER') ?: 'root');
define('DB_PASS', getenv('DB_PASS') ?: '');

// Cloudflare Turnstile Configuration
define('TURNSTILE_SECRET_KEY', getenv('TURNSTILE_SECRET_KEY') ?: 'YOUR_TURNSTILE_SECRET_KEY');
define('TURNSTILE_SITE_KEY', getenv('TURNSTILE_SITE_KEY') ?: 'YOUR_TURNSTILE_SITE_KEY');

// Recipient Webmail
define('ADMIN_EMAIL', 'contactme@joannastephen.com');
define('ADMIN_NAME', 'Joanna Olayemi Stephen');

// Website & Identity
define('SITE_NAME', 'Joanna Olayemi Stephen');
define('SITE_URL', 'https://joannastephen.com');
define('PLATFORM_URL', 'https://exceptionalrootslearning.com');
define('LINKEDIN_URL', 'https://www.linkedin.com/in/joanna-stephen-976418128');

// Optional SMTP Configuration (if using authenticated SMTP instead of native mail())
define('SMTP_ENABLED', filter_var(getenv('SMTP_ENABLED') ?: false, FILTER_VALIDATE_BOOLEAN));
define('SMTP_HOST', getenv('SMTP_HOST') ?: 'mail.joannastephen.com');
define('SMTP_PORT', getenv('SMTP_PORT') ?: 465);
define('SMTP_SECURE', getenv('SMTP_SECURE') ?: 'ssl');
define('SMTP_USER', getenv('SMTP_USER') ?: 'contactme@joannastephen.com');
define('SMTP_PASS', getenv('SMTP_PASS') ?: '');
