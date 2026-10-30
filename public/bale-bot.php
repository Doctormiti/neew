<?php
/**
 * ==============================================================================
 * ONIVAL Bale Bot Entry Point (public_html/bale-bot.php)
 * ==============================================================================
 * Securely delegates to the canonical webhook engine (api/webhook.php)
 * ==============================================================================
 */

$_GET['platform'] = 'bale';
if (!isset($_GET['bot'])) {
    $_GET['bot'] = 'customer';
}
require __DIR__ . '/api/webhook.php';
