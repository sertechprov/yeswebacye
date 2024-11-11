<?php
session_start();

// CORS headers to allow requests from your Cloudflare domain
header("Access-Control-Allow-Origin: https://galadarrirent.com"); // Replace with your actual Cloudflare domain
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json");

// IP Rate Limiting Configuration
$ip = $_SERVER['REMOTE_ADDR'];
$rate_limit = 10; // Max requests per time window
$time_window = 900; // Time window in seconds (1 hour)

// Blocked IPs and allowed referrers
$blocked_ips = ['123.45.67.89', '111.222.333.444']; // Add IPs to block here
$allowed_referrers = ['galadarrirent.com']; // Add trusted referrer domains

// Initialize session for rate-limiting if not already set
if (!isset($_SESSION['requests'])) {
    $_SESSION['requests'] = array();
}
$requests = &$_SESSION['requests'];

// Current timestamp
$now = time();

// Clean up old entries
foreach ($requests as $ip_address => $data) {
    if ($data['last_request'] + $time_window < $now) {
        unset($requests[$ip_address]);
    }
}

// Honeypot check
$hidden_field = $_POST['hidden_address_field'] ?? '';
if (!empty($hidden_field)) {
    echo json_encode(["status" => "fail", "reason" => "bot_detected"]);
    exit();
}

// Mouse movement check
$mouse_movement = $_POST['mouse_movement'] ?? 'bot';
if ($mouse_movement !== 'human') {
    echo json_encode(["status" => "fail", "reason" => "insufficient_interaction"]);
    exit();
}

// Referrer check
$referrer = $_SERVER['HTTP_REFERER'] ?? '';
$is_valid_referrer = empty($referrer); // Allow if referrer is missing
foreach ($allowed_referrers as $allowed) {
    if (stripos($referrer, $allowed) !== false) {
        $is_valid_referrer = true;
        break;
    }
}
if (!$is_valid_referrer) {
    echo json_encode(["status" => "fail", "reason" => "invalid_referrer"]);
    exit();
}

// IP Blocking Check
if (in_array($ip, $blocked_ips)) {
    echo json_encode(["status" => "fail", "reason" => "blocked_ip"]);
    exit();
}

// Rate limiting check
if (isset($requests[$ip])) {
    $requests[$ip]['count']++;
    $requests[$ip]['last_request'] = $now;
    if ($requests[$ip]['count'] > $rate_limit) {
        echo json_encode(["status" => "fail", "reason" => "rate_limit_exceeded"]);
        exit();
    }
} else {
    $requests[$ip] = ['count' => 1, 'last_request' => $now];
}

// Successful verification
echo json_encode(["status" => "success", "reason" => "verified"]);
?>
