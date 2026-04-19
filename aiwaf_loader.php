<?php
declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

use AIWAF\Adapters\InMemoryAdapter;
use AIWAF\AIWAF;
use AIWAF\RateLimiter;
use AIWAF\Logger;
use AIWAF\IPBlocker;
use AIWAF\IsolationForest;

// Initialize rate limiting (in-memory by default)
RateLimiter::initAdapter(new InMemoryAdapter());

// Run full AIWAF protection flow first.
AIWAF::protect();

// Log current request features
Logger::logRequest();

// IP blocking check
if (IPBlocker::isBlocked($_SERVER['REMOTE_ADDR'])) {
    http_response_code(403);
    exit("Access Denied by AIWAF (IP Blocked).");
}

// Build request features array
$features = [
    $_SERVER['REQUEST_METHOD'] ?? '',
    $_SERVER['REQUEST_URI'] ?? '',
    $_SERVER['HTTP_USER_AGENT'] ?? '',
    $_SERVER['REMOTE_ADDR'] ?? '',
    $_SERVER['HTTP_ACCEPT'] ?? '',
    $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
    $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''
];

// Run anomaly detection using Isolation Forest
$model = new IsolationForest();
$model->fit([$features]);  // optionally replace with persistent training data
$prediction = $model->predict([$features], 0.6);

if ($prediction[0] === 1) {
    http_response_code(403);
    exit("Access Denied by AIWAF (Anomaly Detected).");
}
?>
