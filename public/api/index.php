<?php
/**
 * ==============================================================================
 * ONIVAL Production Server API Backend for Shared Hosting (ParsPack / cPanel)
 * ==============================================================================
 * Clean, transactional REST API router backed by canonical server-data storage,
 * robust role-based access control, hardened image handling, and diagnostic tools.
 * ==============================================================================
 */

require_once __DIR__ . '/common.php';

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-Admin-Token');
header('X-Powered-By: Onival-Engine-PHP');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// ------------------------------------------------------------------------------
// 1. Request URL & Method Parser
// ------------------------------------------------------------------------------
$method = $_SERVER['REQUEST_METHOD'];
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($requestUri, PHP_URL_PATH);

if (preg_match('#(/api(?:/.*)?)$#', $path, $matches)) {
    $path = $matches[1];
} elseif (!empty($_GET['path'])) {
    $path = '/api/' . ltrim($_GET['path'], '/');
}
$path = preg_replace('#^/+#', '/', $path);
$path = rtrim($path, '/');
if ($path === '') {
    $path = '/api';
}

$rawInput = file_get_contents('php://input');
$body = @json_decode($rawInput, true) ?: [];

// Webhook routes delegation
if (
    $path === '/api/webhook/bale' ||
    $path === '/api/bot/webhook/bale' ||
    $path === '/api/webhook/bale/customer' ||
    $path === '/api/webhook/bale/admin' ||
    $path === '/api/webhook/telegram' ||
    $path === '/api/bot/webhook/telegram' ||
    $path === '/api/webhook.php' ||
    $path === '/api/bale-webhook.php' ||
    $path === '/api/telegram-webhook.php' ||
    $path === '/api/webhook'
) {
    if (strpos($path, 'admin') !== false) {
        $_GET['bot'] = 'admin';
    }
    require __DIR__ . '/webhook.php';
    exit;
}

// Read-only state for fast querying
$db = loadDatabaseReadonly();

// ------------------------------------------------------------------------------
// 2. Public Storefront & Health Endpoints
// ------------------------------------------------------------------------------
if (($path === '/api/health' || $path === '/api/ping') && $method === 'GET') {
    echo json_encode([
        'ok' => true,
        'status' => 'healthy',
        'serverEngine' => 'Host-PHP-LiteSpeed-Live',
        'timestamp' => date('c')
    ]);
    exit;
}

// Admin Setup Status (Public indicator: whether OTP is currently pending)
if ($path === '/api/admin/setup-status' && $method === 'GET') {
    $creds = $db['adminCredentials'] ?? [];
    $isDone = !empty($creds['initialSetupCompleted']);
    echo json_encode([
        'initialSetupCompleted' => $isDone,
        'defaultUsername' => 'admin',
        'initialOtp' => !$isDone ? 'Onival@Admin2025' : null
    ]);
    exit;
}

// Public Product Catalog
if ($path === '/api/products' && $method === 'GET') {
    $prods = array_values(array_filter($db['products'] ?? [], fn($p) => empty($p['isDelete'])));
    echo json_encode($prods);
    exit;
}

if (preg_match('#^/api/products/(\d+)$#', $path, $m) && $method === 'GET') {
    $pId = (int)$m[1];
    foreach ($db['products'] ?? [] as $prod) {
        if ((int)($prod['id'] ?? 0) === $pId && empty($prod['isDelete'])) {
            echo json_encode($prod);
            exit;
        }
    }
    http_response_code(404);
    echo json_encode(['ok' => false, 'error' => 'محصول یافت نشد']);
    exit;
}

// Public Product Categories
if ($path === '/api/product-categories' && $method === 'GET') {
    echo json_encode($db['productCategories'] ?? []);
    exit;
}

// Public Blog Posts
if ($path === '/api/posts' && $method === 'GET') {
    $posts = array_values(array_filter($db['posts'] ?? [], fn($p) => empty($p['isDelete'])));
    echo json_encode($posts);
    exit;
}

if (preg_match('#^/api/posts/(\d+)$#', $path, $m) && $method === 'GET') {
    $pId = (int)$m[1];
    foreach ($db['posts'] ?? [] as $post) {
        if ((int)($post['id'] ?? 0) === $pId && empty($post['isDelete'])) {
            echo json_encode($post);
            exit;
        }
    }
    http_response_code(404);
    echo json_encode(['ok' => false, 'error' => 'مقاله یافت نشد']);
    exit;
}

// Public Post Categories
if ($path === '/api/post-categories' && $method === 'GET') {
    echo json_encode($db['postCategories'] ?? []);
    exit;
}

// Public Site Content
if ($path === '/api/site-content' && $method === 'GET') {
    echo json_encode($db['siteContent'] ?? []);
    exit;
}

// Public Order Tracking
if (preg_match('#^/api/orders/track/([^/]+)$#', $path, $m) && $method === 'GET') {
    $trackCode = urldecode($m[1]);
    $matched = findOrderByCodePhp($db['orders'] ?? [], $trackCode);
    if ($matched) {
        // Redact internal administrative notes
        $safeOrder = $matched;
        unset($safeOrder['receiptFileId']);
        echo json_encode(['ok' => true, 'order' => $safeOrder]);
    } else {
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'سفارشی با این کد رهگیری یافت نشد']);
    }
    exit;
}

// Public Contact Message Submission
if ($path === '/api/contact' && $method === 'POST') {
    $fullName = trim($body['fullName'] ?? '');
    $phoneNumber = trim($body['phoneNumber'] ?? '');
    $messageText = trim($body['message'] ?? '');

    if (empty($fullName) || empty($messageText)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'نام و متن پیام الزامی است']);
        exit;
    }

    $newMsg = [
        'id' => time() * 1000 + rand(10, 99),
        'fullName' => mb_substr($fullName, 0, 100, 'UTF-8'),
        'phoneNumber' => mb_substr($phoneNumber, 0, 30, 'UTF-8'),
        'message' => mb_substr($messageText, 0, 2000, 'UTF-8'),
        'trackingCode' => 'ONV-' . rand(1000, 9999),
        'creationTime' => date('Y/m/d H:i'),
        'isRead' => false
    ];

    withDatabaseTransaction(function(&$dbRef) use ($newMsg) {
        if (!isset($dbRef['contactMessages']) || !is_array($dbRef['contactMessages'])) {
            $dbRef['contactMessages'] = [];
        }
        array_unshift($dbRef['contactMessages'], $newMsg);
    });

    echo json_encode(['ok' => true, 'message' => 'پیام شما با موفقیت ثبت شد', 'contact' => $newMsg]);
    exit;
}

// Public Order Placement
if ($path === '/api/orders' && $method === 'POST') {
    $userFullName = trim($body['userFullName'] ?? $body['customerName'] ?? '');
    $phoneNumber = trim($body['phoneNumber'] ?? '');
    $userAddress = trim($body['userAddress'] ?? '');
    $items = $body['items'] ?? [];

    if (empty($userFullName) || empty($phoneNumber)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'نام خریدار و شماره تماس الزامی است']);
        exit;
    }

    $generatedCode = 'ONV-ORD-' . rand(10000, 99999);
    $totalPrice = (int)($body['totalPrice'] ?? $body['finalTotal'] ?? 0);

    $botUsername = ltrim(trim((string)($db['telegramConfig']['customerBotUsername'] ?? $db['telegramConfig']['baleBotUsername'] ?? 'Onivalbot')), '@');
    $balePaymentUrl = "https://ble.ir/{$botUsername}?start=pay_{$generatedCode}";

    $newOrder = [
        'id' => time() * 1000 + rand(10, 99),
        'orderNumber' => (string)rand(10000, 99999),
        'trackingCode' => $generatedCode,
        'userFullName' => mb_substr($userFullName, 0, 100, 'UTF-8'),
        'phoneNumber' => mb_substr($phoneNumber, 0, 30, 'UTF-8'),
        'userAddress' => mb_substr($userAddress, 0, 500, 'UTF-8'),
        'postalCode' => trim((string)($body['postalCode'] ?? '')),
        'items' => is_array($items) ? $items : [],
        'totalPrice' => $totalPrice,
        'finalTotal' => $totalPrice,
        'status' => 'Pending',
        'paymentStatus' => 'Unpaid',
        'paymentMethod' => $body['paymentMethod'] ?? 'card_to_card',
        'balePaymentUrl' => $balePaymentUrl,
        'creationTime' => date('Y/m/d'),
        'inventoryDeducted' => false
    ];

    $res = withDatabaseTransaction(function(&$dbRef) use ($newOrder) {
        if (!isset($dbRef['orders']) || !is_array($dbRef['orders'])) {
            $dbRef['orders'] = [];
        }
        array_unshift($dbRef['orders'], $newOrder);
        return $newOrder;
    });

    onival_log('order', 'order_placed', "Order {$generatedCode} placed", ['amount' => $totalPrice]);
    echo json_encode(['ok' => true, 'order' => $res]);
    exit;
}

// Public Upload Receipt (Card-to-Card)
if (preg_match('#^/api/orders/([^/]+)/upload-receipt$#', $path, $m) && $method === 'POST') {
    $orderIdOrCode = $m[1];
    $receiptImage = $body['receiptImage'] ?? '';

    // Strictly whitelist MIME types: png, jpeg, jpg, webp (blocks svg/xml XSS)
    if (!preg_match('#^data:image\/(png|jpe?g|webp);base64,(.+)$#i', $receiptImage, $imgMatch)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'فرمت تصویر نامعتبر است. تنها فرمت‌های PNG، JPG و WEBP مجاز هستند.']);
        exit;
    }

    $ext = strtolower($imgMatch[1]);
    if ($ext === 'jpeg') $ext = 'jpg';
    $binData = base64_decode($imgMatch[2], true);

    if ($binData === false || strlen($binData) < 20 || strlen($binData) > 5242880) { // Max 5MB
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'حجم فایل تصویر نامعتبر یا بیش از ۵ مگابایت است.']);
        exit;
    }

    $receiptFileName = 'receipt_' . uniqid() . '.' . $ext;
    $receiptFilePath = $receiptsDir . '/' . $receiptFileName;

    if (@file_put_contents($receiptFilePath, $binData, LOCK_EX) === false) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'خطا در ذخیره‌سازی فایل رسید در سرور']);
        exit;
    }

    $savedUrl = '/api/admin/receipts/' . $receiptFileName;

    $updatedOrder = withDatabaseTransaction(function(&$dbRef) use ($orderIdOrCode, $savedUrl) {
        $matched = findOrderByCodePhp($dbRef['orders'] ?? [], $orderIdOrCode);
        if (!$matched) {
            foreach ($dbRef['orders'] ?? [] as $ord) {
                if ((string)($ord['id'] ?? '') === (string)$orderIdOrCode) {
                    $matched = $ord;
                    break;
                }
            }
        }
        if (!$matched) return null;

        foreach ($dbRef['orders'] as &$ord) {
            if (($ord['trackingCode'] ?? '') === $matched['trackingCode']) {
                $ord['receiptImage'] = $savedUrl;
                $ord['paymentStatus'] = 'PendingVerification';
                $ord['receiptUploadedAt'] = date('c');
                return $ord;
            }
        }
        return null;
    });

    if (!$updatedOrder) {
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'سفارش مورد نظر جهت ثبت فیش یافت نشد']);
        exit;
    }

    onival_log('receipt', 'web_receipt_uploaded', "Web receipt uploaded for {$updatedOrder['trackingCode']}");
    echo json_encode([
        'ok' => true,
        'message' => 'تصویر فیش واریزی با موفقیت بارگذاری شد و در انتظار تایید مدیریت است.',
        'receiptUrl' => $savedUrl,
        'order' => $updatedOrder
    ]);
    exit;
}

// ------------------------------------------------------------------------------
// 3. Admin Authentication & Session Management
// ------------------------------------------------------------------------------

// Rate limit helper: max 5 failed attempts per 60s per IP
function checkAdminLoginRateLimit() {
    global $canonicalDataDir;
    $ipHash = hash('sha256', $_SERVER['REMOTE_ADDR'] ?? 'local');
    $rlFile = $canonicalDataDir . '/.login_rl_' . substr($ipHash, 0, 16);
    $now = time();
    $data = ['count' => 0, 'firstAttempt' => $now];

    if (file_exists($rlFile)) {
        $stored = @json_decode(@file_get_contents($rlFile), true);
        if (is_array($stored) && ($now - ($stored['firstAttempt'] ?? 0)) < 60) {
            $data = $stored;
        }
    }
    return ['allowed' => ($data['count'] < 5), 'current' => $data, 'file' => $rlFile];
}

function recordAdminLoginFailure($rl) {
    $now = time();
    $rl['current']['count']++;
    @file_put_contents($rl['file'], json_encode($rl['current']), LOCK_EX);
}

function clearAdminLoginRateLimit($rl) {
    if (file_exists($rl['file'])) {
        @unlink($rl['file']);
    }
}

// POST /api/admin/login
if ($path === '/api/admin/login' && $method === 'POST') {
    $rl = checkAdminLoginRateLimit();
    if (!$rl['allowed']) {
        http_response_code(429);
        echo json_encode(['ok' => false, 'error' => 'تعداد تلاش‌های ناموفق شما بیش از حد مجاز بوده است. لطفاً ۶۰ ثانیه دیگر مجدداً تلاش نمایید.']);
        exit;
    }

    $u = trim($body['username'] ?? $body['email'] ?? '');
    $p = trim($body['password'] ?? '');
    $creds = $db['adminCredentials'] ?? [];

    $isInitialPending = empty($creds['initialSetupCompleted']);
    $validUser = strtolower(trim($creds['username'] ?? 'admin'));
    $validEmail = strtolower(trim($creds['email'] ?? ''));
    $validPass = trim($creds['password'] ?? 'admin');

    if (empty($u) || empty($p)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'نام کاربری و رمز عبور الزامی است.']);
        exit;
    }

    if (!$isInitialPending) {
        if ($p === 'Onival@Admin2025' || $p === ($creds['oneTimePassword'] ?? '')) {
            recordAdminLoginFailure($rl);
            http_response_code(401);
            echo json_encode(['ok' => false, 'error' => 'رمز عبور یکبار مصرف اولیه منقضی شده است. لطفاً با نام کاربری و رمز عبور دائمی جدید خود وارد شوید.']);
            exit;
        }
    }

    $isUserMatch = (strtolower($u) === $validUser || (!empty($validEmail) && strtolower($u) === $validEmail));
    if ($isInitialPending && strtolower($u) === 'admin') {
        $isUserMatch = true;
    }

    $isPassMatch = false;
    if ($isUserMatch) {
        $isPassMatch = verifyAdminPassword($p, $validPass, $isInitialPending);
    }

    if ($isUserMatch && $isPassMatch) {
        clearAdminLoginRateLimit($rl);
        $token = generateAdminSessionToken($creds['username'] ?? 'admin', $creds['password'] ?? 'admin');
        echo json_encode([
            'ok' => true,
            'success' => true,
            'token' => $token,
            'profile' => [
                'username' => $creds['username'] ?? 'admin',
                'name' => $creds['name'] ?? 'مدیریت اونیوال (ONIVAL Admin)',
                'email' => $creds['email'] ?? '',
                'initialSetupCompleted' => !empty($creds['initialSetupCompleted'])
            ],
            'isInitialPending' => $isInitialPending,
            'message' => $isInitialPending
                ? 'ورود اولیه با موفقیت انجام شد. لطفاً در پنل، نام کاربری و رمز عبور دائمی جدید خود را ثبت فرمایید.'
                : 'ورود به پنل مدیریت با موفقیت انجام شد.'
        ]);
        exit;
    }

    recordAdminLoginFailure($rl);
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'نام کاربری یا رمز عبور اشتباه است.']);
    exit;
}

// POST /api/admin/logout
if ($path === '/api/admin/logout' && $method === 'POST') {
    getAdminSessionSecret(); // triggers secret rotation if file modified
    $newSecret = bin2hex(random_bytes(32));
    @file_put_contents($secretFile, $newSecret, LOCK_EX);
    echo json_encode(['ok' => true, 'message' => 'خروج از حساب مدیریت با موفقیت انجام شد.']);
    exit;
}

// GET /api/admin/verify-session
if ($path === '/api/admin/verify-session' && $method === 'GET') {
    if (isRequestAdminAuthorized($db)) {
        $creds = $db['adminCredentials'] ?? [];
        echo json_encode([
            'ok' => true,
            'profile' => [
                'username' => $creds['username'] ?? 'admin',
                'name' => $creds['name'] ?? 'مدیریت اونیوال (ONIVAL Admin)',
                'email' => $creds['email'] ?? '',
                'initialSetupCompleted' => !empty($creds['initialSetupCompleted'])
            ]
        ]);
        exit;
    }
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'نشست کاربری نامعتبر یا منقضی شده است.']);
    exit;
}

// GET /api/account/profile
if ($path === '/api/account/profile' && $method === 'GET') {
    $creds = $db['adminCredentials'] ?? [];
    echo json_encode([
        'username' => $creds['username'] ?? 'admin',
        'email' => $creds['email'] ?? 'admin@onival.com',
        'name' => $creds['name'] ?? 'مدیریت اونیوال (ONIVAL Admin)',
        'initialSetupCompleted' => !empty($creds['initialSetupCompleted']),
        'siteLogo' => $db['siteContent']['siteLogo'] ?? ''
    ]);
    exit;
}

// POST /api/account/change-credentials
if ($path === '/api/account/change-credentials' && $method === 'POST') {
    if (!isRequestAdminAuthorized($db)) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'دسترسی غیرمجاز. لطفاً ابتدا وارد حساب مدیریت شوید.']);
        exit;
    }

    $u = trim($body['username'] ?? '');
    $curPass = trim($body['currentPassword'] ?? '');
    $newPass = trim($body['newPassword'] ?? '');
    $email = trim($body['email'] ?? '');
    $name = trim($body['name'] ?? '');

    $creds = $db['adminCredentials'] ?? [];
    $isInitialPending = empty($creds['initialSetupCompleted']);
    $validPass = trim($creds['password'] ?? 'admin');

    if (!$isInitialPending && !empty($newPass)) {
        if (empty($curPass) || !verifyAdminPassword($curPass, $validPass, false)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'رمز عبور فعلی مدیریت اشتباه است.']);
            exit;
        }
    }

    if (!empty($newPass) && strlen($newPass) < 6) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'رمز عبور جدید باید حداقل ۶ کاراکتر باشد.']);
        exit;
    }

    $res = withDatabaseTransaction(function(&$dbRef) use ($u, $newPass, $email, $name, $secretFile) {
        if (!isset($dbRef['adminCredentials'])) {
            $dbRef['adminCredentials'] = [];
        }
        $c = &$dbRef['adminCredentials'];
        if (!empty($u)) $c['username'] = $u;
        if (!empty($email)) $c['email'] = $email;
        if (!empty($name)) $c['name'] = $name;

        if (!empty($newPass)) {
            $c['password'] = hashAdminPassword($newPass);
        }
        $c['initialSetupCompleted'] = true;
        $c['oneTimePassword'] = null;
        $c['oneTimePasswordExpired'] = true;

        // Invalidate previous sessions
        $newSecret = bin2hex(random_bytes(32));
        @file_put_contents($secretFile, $newSecret, LOCK_EX);

        return $c;
    });

    if (!$res) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'خطا در ثبت اطلاعات در دیسک هاست.']);
        exit;
    }

    $freshToken = generateAdminSessionToken($res['username'] ?? 'admin', $res['password'] ?? 'admin');
    onival_log('account', 'credentials_updated', 'Admin credentials updated and previous sessions invalidated');

    echo json_encode([
        'ok' => true,
        'token' => $freshToken,
        'profile' => [
            'username' => $res['username'],
            'email' => $res['email'],
            'name' => $res['name'],
            'initialSetupCompleted' => true
        ],
        'message' => 'نام کاربری و رمز عبور دائمی جدید با موفقیت ثبت شد. رمز موقت اولیه برای همیشه باطل گردید.'
    ]);
    exit;
}

// ------------------------------------------------------------------------------
// 4. Protected Administration Endpoints (Require Admin Auth)
// ------------------------------------------------------------------------------

// All remaining administrative endpoints require verified admin authorization
function enforceAdminAuthOrExit($db) {
    if (!isRequestAdminAuthorized($db)) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'دسترسی غیرمجاز (401 Unauthorized)']);
        exit;
    }
}

// GET /api/stats
if ($path === '/api/stats' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    $activeProds = array_filter($db['products'] ?? [], fn($p) => empty($p['isDelete']));
    echo json_encode([
        'totalProducts' => count($activeProds),
        'totalPosts' => count($db['posts'] ?? []),
        'pendingOrders' => count(array_filter($db['orders'] ?? [], fn($o) => ($o['status'] ?? '') === 'Pending')),
        'unreadMessages' => count(array_filter($db['contactMessages'] ?? [], fn($m) => empty($m['isRead']))),
        'totalRevenue' => array_reduce($db['orders'] ?? [], fn($carry, $o) => $carry + (int)($o['totalPrice'] ?? 0), 0),
        'serverEngine' => 'Host-PHP-LiteSpeed-Live'
    ]);
    exit;
}

// GET /api/admin/receipts/:filename (Protected Receipt Image Server)
if (preg_match('#^/api/admin/receipts/([a-zA-Z0-9._-]+)$#', $path, $m) && $method === 'GET') {
    $reqAuth = false;
    if (isRequestAdminAuthorized($db)) {
        $reqAuth = true;
    } elseif (!empty($_GET['token'])) {
        // Allow query token for <img> tags
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $_GET['token'];
        if (isRequestAdminAuthorized($db)) {
            $reqAuth = true;
        }
    }

    if (!$reqAuth) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'Unauthorized']);
        exit;
    }

    $fileName = basename($m[1]);
    $filePath = $receiptsDir . '/' . $fileName;

    if (!file_exists($filePath)) {
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'فایل رسید یافت نشد']);
        exit;
    }

    header('Content-Security-Policy: default-src \'none\'; img-src \'self\' data:; style-src \'unsafe-inline\'');
    header('X-Content-Type-Options: nosniff');
    $mime = mime_content_type($filePath) ?: 'image/jpeg';
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($filePath));
    readfile($filePath);
    exit;
}

// Orders Management
if ($path === '/api/orders' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    echo json_encode($db['orders'] ?? []);
    exit;
}

if (preg_match('#^/api/orders/(\d+)$#', $path, $m) && $method === 'PUT') {
    enforceAdminAuthOrExit($db);
    $orderId = (int)$m[1];
    $updated = withDatabaseTransaction(function(&$dbRef) use ($orderId, $body) {
        foreach ($dbRef['orders'] as &$ord) {
            if ((int)($ord['id'] ?? 0) === $orderId) {
                $ord = array_merge($ord, $body);
                return $ord;
            }
        }
        return null;
    });
    if ($updated) {
        echo json_encode(['ok' => true, 'order' => $updated]);
    } else {
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'سفارش یافت نشد']);
    }
    exit;
}

// POST /api/orders/:id/approve-payment
if (preg_match('#^/api/orders/([^/]+)/approve-payment$#', $path, $m) && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $orderIdOrCode = $m[1];

    $res = withDatabaseTransaction(function(&$dbRef) use ($orderIdOrCode) {
        $order = findOrderByCodePhp($dbRef['orders'] ?? [], $orderIdOrCode);
        if (!$order) {
            foreach ($dbRef['orders'] ?? [] as $ord) {
                if ((string)($ord['id'] ?? '') === (string)$orderIdOrCode) {
                    $order = $ord;
                    break;
                }
            }
        }
        if (!$order) return ['ok' => false, 'error' => 'سفارش یافت نشد'];

        foreach ($dbRef['orders'] as &$ord) {
            if (($ord['trackingCode'] ?? '') === $order['trackingCode']) {
                $inv = deductOrderInventory($dbRef, $ord);
                if (!$inv['ok']) return ['ok' => false, 'error' => $inv['error']];
                $ord['paymentStatus'] = 'Paid';
                $ord['status'] = 'Processing';
                $ord['approvedAt'] = date('c');
                return ['ok' => true, 'order' => $ord];
            }
        }
        return ['ok' => false, 'error' => 'خطا در ثبت تایید سفارش'];
    });

    if (!empty($res['ok'])) {
        $approvedOrder = $res['order'];
        $customerToken = trim((string)($db['telegramConfig']['customerBotToken'] ?? $db['telegramConfig']['baleBotToken'] ?? ''));
        $custChat = $approvedOrder['baleChatId'] ?? $approvedOrder['chatId'] ?? null;
        if ($custChat && !empty($customerToken)) {
            $msg = "🎉 خریدار گرامی، فیش واریزی سفارش {$approvedOrder['trackingCode']} توسط مدیریت تایید گردید و مرسوله شما وارد مرحله بسته‌بندی شد. 📦";
            sendBaleMessage($customerToken, $custChat, $msg);
        }
        echo json_encode(['ok' => true, 'order' => $approvedOrder]);
    } else {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => $res['error'] ?? 'خطا در تایید']);
    }
    exit;
}

// ------------------------------------------------------------------------------
// 5. Bot Management, Webhook & Diagnostics Endpoints
// ------------------------------------------------------------------------------

// GET /api/bot/config (Strips secrets, returns safe flags)
if ($path === '/api/bot/config' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    $cfg = $db['telegramConfig'] ?? [];
    $safe = $cfg;

    $safe['hasCustomerToken'] = !empty($cfg['customerBotToken'] || $cfg['baleBotToken'] || $cfg['botToken']);
    $safe['hasAdminToken'] = !empty($cfg['adminBotToken'] || $cfg['baleAdminBotToken']);
    $safe['hasWalletLiveToken'] = !empty($cfg['balePaymentTokenLive'] || $cfg['balePaymentToken']);
    $safe['hasWalletTestToken'] = !empty($cfg['balePaymentTokenTest']);

    unset($safe['botToken'], $safe['baleBotToken'], $safe['customerBotToken'], $safe['adminBotToken']);
    unset($safe['balePaymentTokenLive'], $safe['balePaymentTokenTest'], $safe['balePaymentToken'], $safe['webhookSecretToken']);

    echo json_encode(['ok' => true, 'config' => $safe]);
    exit;
}

// POST /api/bot/config (Blank secret fields preserve stored values)
if ($path === '/api/bot/config' && $method === 'POST') {
    enforceAdminAuthOrExit($db);

    $saved = withDatabaseTransaction(function(&$dbRef) use ($body) {
        if (!isset($dbRef['telegramConfig'])) $dbRef['telegramConfig'] = [];
        $cur = &$dbRef['telegramConfig'];

        // Sensitive secret fields: update only if non-empty
        $secretKeys = ['customerBotToken', 'adminBotToken', 'botToken', 'baleBotToken', 'balePaymentTokenLive', 'balePaymentTokenTest', 'balePaymentToken', 'webhookSecretToken'];
        foreach ($secretKeys as $sk) {
            if (isset($body[$sk]) && trim((string)$body[$sk]) !== '') {
                $cur[$sk] = trim((string)$body[$sk]);
            }
        }

        // Non-secret fields: update directly
        $normalKeys = [
            'customerBotUsername', 'customerBotEnabled', 'adminBotUsername', 'adminChatId', 'adminBotEnabled',
            'baleAdminChatId', 'baleAdminUsername', 'baleBotUsername', 'balePaymentMode', 'baseUrl',
            'baleAutoSendInvoice', 'baleAutoNotifyAdminAllTransactions', 'baleAdminDirectApproval', 'active'
        ];
        foreach ($normalKeys as $nk) {
            if (isset($body[$nk])) {
                $cur[$nk] = $body[$nk];
            }
        }
        return $cur;
    });

    onival_log('bot_config', 'config_saved', 'Bot configuration saved durably on host');
    echo json_encode(['ok' => true, 'saved' => true, 'message' => 'تنظیمات ربات‌ها با موفقیت در دیسک هاست ذخیره شد.']);
    exit;
}

// POST /api/bot/test-connection & /api/bot/test-customer-bot
if (($path === '/api/bot/test-connection' || $path === '/api/bot/test-customer-bot') && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $tg = $db['telegramConfig'] ?? [];
    $token = trim((string)($body['token'] ?? $body['botToken'] ?? $tg['customerBotToken'] ?? $tg['baleBotToken'] ?? $tg['botToken'] ?? ''));

    if (empty($token)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'توکن ربات مشتری وارد نشده است.']);
        exit;
    }

    $me = callBaleApi($token, 'getMe');
    if (!empty($me['ok'])) {
        echo json_encode([
            'ok' => true,
            'connected' => true,
            'botUser' => $me['result']['username'] ?? 'Onivalbot',
            'botInfo' => $me['result'],
            'message' => 'اتصال به ربات مشتری با موفقیت تایید شد.'
        ]);
    } else {
        echo json_encode([
            'ok' => false,
            'connected' => false,
            'status' => $me['http_code'] ?? 400,
            'description' => $me['description'] ?? 'خطا در ارتباط با وب‌سرویس بله',
            'error' => $me['description'] ?? 'توکن نامعتبر است'
        ]);
    }
    exit;
}

// POST /api/bot/test-admin-bot
if ($path === '/api/bot/test-admin-bot' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $tg = $db['telegramConfig'] ?? [];
    $token = trim((string)($body['token'] ?? $body['botToken'] ?? $tg['adminBotToken'] ?? $tg['baleAdminBotToken'] ?? ''));

    if (empty($token)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'توکن ربات ادمین وارد نشده است.']);
        exit;
    }

    $me = callBaleApi($token, 'getMe');
    if (!empty($me['ok'])) {
        echo json_encode([
            'ok' => true,
            'connected' => true,
            'botUser' => $me['result']['username'] ?? 'onivaladminbot',
            'botInfo' => $me['result'],
            'message' => 'اتصال به ربات اختصاصی ادمین با موفقیت تایید شد.'
        ]);
    } else {
        echo json_encode([
            'ok' => false,
            'connected' => false,
            'status' => $me['http_code'] ?? 400,
            'description' => $me['description'] ?? 'خطا در ارتباط با وب‌سرویس بله'
        ]);
    }
    exit;
}

// POST /api/bot/test-admin-welcome
if ($path === '/api/bot/test-admin-welcome' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $tg = $db['telegramConfig'] ?? [];
    $token = trim((string)($body['token'] ?? $body['botToken'] ?? $tg['adminBotToken'] ?? $tg['customerBotToken'] ?? ''));
    $chatId = trim((string)($body['chatId'] ?? $tg['adminChatId'] ?? $tg['baleAdminChatId'] ?? '69451465'));

    if (empty($token) || empty($chatId)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'توکن ربات یا شناسه چت ادمین وارد نشده است.']);
        exit;
    }

    $text = "اتصال ربات به هاست با موفقیت انجام شد. شما به عنوان ادمین شناسایی شدید\nزمان: " . date('Y/m/d - H:i:s');
    $send = sendBaleMessage($token, $chatId, $text);

    if (!empty($send['ok'])) {
        echo json_encode([
            'ok' => true,
            'delivered' => true,
            'messageId' => $send['result']['message_id'] ?? null,
            'message' => 'پیام با موفقیت به بله ادمین ارسال گردید.'
        ]);
    } else {
        $desc = $send['description'] ?? 'خطا در ارسال';
        $isForbidden = (strpos($desc, 'Forbidden') !== false || ($send['http_code'] ?? 0) === 403);
        echo json_encode([
            'ok' => false,
            'delivered' => false,
            'status' => $send['http_code'] ?? 400,
            'description' => $desc,
            'forbiddenStartRequired' => $isForbidden,
            'message' => $isForbidden
                ? 'خطای ۴۰۳ بله: ربات نمی‌تواند شروع‌کننده مکالمه باشد. لطفاً ابتدا در بله دکمه Start را به ربات ارسال فرمایید.'
                : "پاسخ بله: {$desc}"
        ]);
    }
    exit;
}

// POST /api/bot/test-send-invoice
if ($path === '/api/bot/test-send-invoice' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $tg = $db['telegramConfig'] ?? [];
    $token = trim((string)($tg['customerBotToken'] ?? $tg['baleBotToken'] ?? ''));
    $chatId = trim((string)($body['chatId'] ?? $tg['adminChatId'] ?? '69451465'));
    $paymentMode = strtolower(trim((string)($tg['balePaymentMode'] ?? 'live')));

    $walletToken = ($paymentMode === 'test')
        ? trim((string)($tg['balePaymentTokenTest'] ?? 'WALLET-TEST-1111111111111111'))
        : trim((string)($tg['balePaymentTokenLive'] ?? $tg['balePaymentToken'] ?? ''));

    if (empty($token) || empty($chatId) || empty($walletToken)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'message' => 'توکن ربات، شناسه چت یا توکن کیف‌پول تنظیم نشده است.']);
        exit;
    }

    $prices = [['label' => 'فاکتور تستی اونیوال', 'amount' => 1500000]]; // 150,000 Toman in Rials
    $invRes = sendBaleInvoiceSafe($token, $chatId, 'فاکتور تستی کیف‌پول', 'تست صدور فاکتور رسمی بله', 'diag_' . time(), $walletToken, 'IRR', $prices, $paymentMode);

    if (!empty($invRes['ok'])) {
        echo json_encode(['ok' => true, 'message' => 'فاکتور آزمایشی با موفقیت به بله ارسال گردید.', 'apiResult' => $invRes]);
    } else {
        echo json_encode(['ok' => false, 'message' => $invRes['error'] ?? ($invRes['description'] ?? 'خطا در ارسال فاکتور'), 'apiResult' => $invRes]);
    }
    exit;
}

// POST /api/bot/webhook-action
if ($path === '/api/bot/webhook-action' && $method === 'POST') {
    enforceAdminAuthOrExit($db);
    $botScope = $body['bot'] ?? 'customer'; // 'customer' or 'admin'
    $action = $body['action'] ?? 'info';   // 'info', 'set', 'delete'
    $tg = $db['telegramConfig'] ?? [];

    $token = ($botScope === 'admin')
        ? trim((string)($tg['adminBotToken'] ?? ''))
        : trim((string)($tg['customerBotToken'] ?? $tg['baleBotToken'] ?? ''));

    if (empty($token)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'message' => "توکن ربات {$botScope} تنظیم نشده است."]);
        exit;
    }

    $canonicalHookUrl = "https://onival.ir/api/webhook/bale?bot={$botScope}";

    if ($action === 'set') {
        $sec = trim((string)($tg['webhookSecretToken'] ?? ''));
        $params = ['url' => $canonicalHookUrl];
        if (!empty($sec)) {
            $params['secret_token'] = $sec;
        }
        $res = callBaleApi($token, 'setWebhook', $params);
        $ok = !empty($res['ok']);
        echo json_encode([
            'ok' => $ok,
            'message' => $ok ? "وب‌هوک ربات {$botScope} با موفقیت ثبت شد." : ($res['description'] ?? 'خطا در ثبت وب‌هوک'),
            'apiData' => $res
        ]);
        exit;
    } elseif ($action === 'delete') {
        $res = callBaleApi($token, 'deleteWebhook', []);
        $ok = !empty($res['ok']);
        echo json_encode([
            'ok' => $ok,
            'message' => $ok ? "وب‌هوک ربات {$botScope} حذف گردید." : ($res['description'] ?? 'خطا در حذف وب‌هوک'),
            'apiData' => $res
        ]);
        exit;
    } else {
        // getWebhookInfo
        $res = callBaleApi($token, 'getWebhookInfo', []);
        echo json_encode([
            'ok' => !empty($res['ok']),
            'apiData' => $res,
            'message' => !empty($res['ok']) ? 'استعلام وب‌هوک دریافت شد.' : ($res['description'] ?? 'خطا در استعلام')
        ]);
        exit;
    }
}

// GET & POST /api/admin/diagnostics
if ($path === '/api/admin/diagnostics' || $path === '/api/admin/diagnostics/run') {
    enforceAdminAuthOrExit($db);
    $suite = runDiagnosticsSuite($db);
    echo json_encode($suite);
    exit;
}

// GET /api/admin/logs
if ($path === '/api/admin/logs' && $method === 'GET') {
    enforceAdminAuthOrExit($db);
    $lines = [];
    if (file_exists($logFile)) {
        $raw = @file_get_contents($logFile);
        if ($raw) {
            $rawLines = array_filter(explode("\n", trim($raw)));
            foreach (array_slice($rawLines, -100) as $rl) {
                $dec = @json_decode($rl, true);
                if (is_array($dec)) $lines[] = $dec;
            }
        }
    }
    echo json_encode(['ok' => true, 'logs' => array_reverse($lines)]);
    exit;
}

// Fallback 404
http_response_code(404);
echo json_encode(['ok' => false, 'error' => "مسیر وب‌سرویس '{$path}' یافت نشد."]);
