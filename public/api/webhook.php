<?php
/**
 * ==============================================================================
 * ONIVAL Unified Bale & Telegram Webhook Processor
 * ==============================================================================
 * Single active webhook engine supporting dedicated customer and admin bots,
 * atomic inventory deduction, and verified Bale wallet / receipt payments.
 * ==============================================================================
 */

require_once __DIR__ . '/common.php';

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    echo json_encode(['ok' => true]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    echo json_encode(['ok' => true, 'service' => 'onival-bale-webhook', 'status' => 'active']);
    exit;
}

$db = loadDatabaseReadonly();
$tgCfg = $db['telegramConfig'] ?? [];
$siteCfg = $db['siteContent'] ?? [];
$payCfg = $siteCfg['paymentConfig'] ?? [];

// ------------------------------------------------------------------------------
// 1. Webhook Secret Token Verification (Fail-Closed)
// ------------------------------------------------------------------------------
$configuredSecret = trim((string)($tgCfg['webhookSecretToken'] ?? ''));
if ($configuredSecret !== '') {
    $incomingSecret = $_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] ?? ($_GET['secret'] ?? '');
    if (empty($incomingSecret) || !hash_equals($configuredSecret, $incomingSecret)) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'error' => 'Forbidden: Invalid webhook secret']);
        onival_log('webhook', 'auth_failure', 'Webhook secret token mismatch or missing');
        exit;
    }
}

// ------------------------------------------------------------------------------
// 2. Resolve Platform, Bot Scope, Tokens & Configured Identities
// ------------------------------------------------------------------------------
$scope = strtolower(trim($_GET['bot'] ?? 'customer')); // 'customer' or 'admin'
$customerToken = trim((string)($tgCfg['customerBotToken'] ?? $tgCfg['baleBotToken'] ?? $tgCfg['botToken'] ?? ''));
$adminToken = trim((string)($tgCfg['adminBotToken'] ?? $tgCfg['baleAdminBotToken'] ?? ''));
$activeToken = ($scope === 'admin' && !empty($adminToken)) ? $adminToken : $customerToken;

// Admin chat identity: must be strictly numeric
$adminChatId = trim((string)($tgCfg['adminChatId'] ?? $tgCfg['baleAdminChatId'] ?? '69451465'));
if (empty($adminChatId)) {
    $adminChatId = '69451465';
}

$customerBotUsername = ltrim(trim((string)($tgCfg['customerBotUsername'] ?? $tgCfg['baleBotUsername'] ?? 'Onivalbot')), '@');
$adminBotUsername = ltrim(trim((string)($tgCfg['adminBotUsername'] ?? 'onivaladminbot')), '@');

$paymentMode = strtolower(trim((string)($tgCfg['balePaymentMode'] ?? 'live')));
$walletToken = '';
if ($paymentMode === 'test') {
    $walletToken = trim((string)($tgCfg['balePaymentTokenTest'] ?? 'WALLET-TEST-1111111111111111'));
} else {
    $walletToken = trim((string)($tgCfg['balePaymentTokenLive'] ?? $tgCfg['balePaymentToken'] ?? ''));
}

$cardNumber = trim((string)($payCfg['cardNumber'] ?? '۶۰۳۷-۹۹۷۵-۹۹۱۲-۳۴۵۶'));
$cardHolder = trim((string)($payCfg['cardHolderName'] ?? 'مجموعه تخصصی فرآورده‌های ارگانیک اونیوال'));
$bankName   = trim((string)($payCfg['bankName'] ?? 'بانک ملی ایران'));
$storeUrl   = 'https://onival.ir';

// ------------------------------------------------------------------------------
// 3. Parse Incoming Payload
// ------------------------------------------------------------------------------
$rawInput = file_get_contents('php://input');
$update = @json_decode($rawInput, true);

if (!$update || !is_array($update)) {
    echo json_encode(['ok' => false, 'error' => 'No valid JSON payload']);
    exit;
}

$correlationId = onival_log('webhook', 'update_received', 'Received update from Bale', [
    'update_id' => $update['update_id'] ?? null,
    'scope' => $scope
]);

// ------------------------------------------------------------------------------
// 4. Handle pre_checkout_query (Bale Wallet Payment Verification)
// ------------------------------------------------------------------------------
if (isset($update['pre_checkout_query'])) {
    $pcq = $update['pre_checkout_query'];
    $pcqId = $pcq['id'] ?? '';
    $orderPayload = $pcq['invoice_payload'] ?? '';
    $cleanOrderCode = str_replace(['_', 'pay-', 'order-'], ['-', '', ''], $orderPayload);

    $matchedOrder = findOrderByCodePhp($db['orders'] ?? [], $cleanOrderCode);
    $paidRials = intval($pcq['total_amount'] ?? 0);

    if ($matchedOrder) {
        $expectedToman = getOrderAmountTomanPhp($matchedOrder);
        $expectedRials = round($expectedToman * 10);

        if ($expectedRials > 0 && $paidRials < $expectedRials) {
            callBaleApi($activeToken, 'answerPreCheckoutQuery', [
                'pre_checkout_query_id' => $pcqId,
                'ok' => false,
                'error_message' => 'مبلغ پرداختی کمتر از مبلغ فاکتور سفارش است.'
            ]);
            onival_log('payment', 'pre_checkout_underpaid', 'Amount mismatch in pre_checkout_query', [
                'orderCode' => $cleanOrderCode,
                'paidRials' => $paidRials,
                'expectedRials' => $expectedRials
            ], $correlationId);
            echo json_encode(['ok' => false, 'error' => 'Insufficient payment amount']);
            exit;
        }

        if (($matchedOrder['paymentStatus'] ?? '') === 'Paid') {
            callBaleApi($activeToken, 'answerPreCheckoutQuery', [
                'pre_checkout_query_id' => $pcqId,
                'ok' => false,
                'error_message' => 'این سفارش قبلاً پرداخت و نهایی شده است.'
            ]);
            echo json_encode(['ok' => false, 'error' => 'Order already paid']);
            exit;
        }
    }

    callBaleApi($activeToken, 'answerPreCheckoutQuery', [
        'pre_checkout_query_id' => $pcqId,
        'ok' => true
    ]);

    onival_log('payment', 'pre_checkout_approved', "Pre-checkout approved for {$cleanOrderCode}", [], $correlationId);
    echo json_encode(['ok' => true]);
    exit;
}

// ------------------------------------------------------------------------------
// 5. Handle callback_query (Buttons & Admin Actions)
// ------------------------------------------------------------------------------
if (isset($update['callback_query'])) {
    $cb = $update['callback_query'];
    $cbId = $cb['id'] ?? '';
    $cbData = $cb['data'] ?? '';
    $cbChatId = (string)($cb['message']['chat']['id'] ?? ($cb['from']['id'] ?? ''));

    callBaleApi($activeToken, 'answerCallbackQuery', [
        'callback_query_id' => $cbId,
        'text' => 'در حال پردازش...'
    ]);

    // Admin confirmation of receipt payment
    if (strpos($cbData, 'confirm_') === 0 || strpos($cbData, 'approve_') === 0) {
        if ($cbChatId !== $adminChatId) {
            sendBaleMessage($activeToken, $cbChatId, "⛔ دسترسی غیرمجاز: تنها شناسه عددی ادمین فروشگاه مجاز به تایید سفارش‌ها است.");
            onival_log('security', 'unauthorized_confirm_attempt', "Non-admin tried to confirm receipt: {$cbChatId}", [], $correlationId);
            echo json_encode(['ok' => false, 'error' => 'Unauthorized']);
            exit;
        }

        $codeToConfirm = preg_replace('/^(confirm_|approve_)/', '', $cbData);

        $txResult = withDatabaseTransaction(function(&$dbRef) use ($codeToConfirm, $cbChatId, $storeUrl, $customerToken, $adminToken, $activeToken) {
            $order = findOrderByCodePhp($dbRef['orders'] ?? [], $codeToConfirm);
            if (!$order) {
                return ['ok' => false, 'error' => 'سفارش یافت نشد'];
            }

            foreach ($dbRef['orders'] as &$ord) {
                if (($ord['trackingCode'] ?? '') === $order['trackingCode'] || (string)($ord['id'] ?? '') === (string)$order['id']) {
                    if (($ord['paymentStatus'] ?? '') === 'Paid') {
                        return ['ok' => true, 'alreadyPaid' => true, 'order' => $ord];
                    }
                    $invRes = deductOrderInventory($dbRef, $ord);
                    if (!$invRes['ok']) {
                        return ['ok' => false, 'error' => $invRes['error']];
                    }
                    $ord['paymentStatus'] = 'Paid';
                    $ord['status'] = 'Processing';
                    $ord['approvedAt'] = date('c');
                    return ['ok' => true, 'order' => $ord];
                }
            }
            return ['ok' => false, 'error' => 'خطا در ثبت سفارش'];
        });

        if ($txResult['ok']) {
            $ordObj = $txResult['order'];
            $custName = $ordObj['userFullName'] ?? $ordObj['customerName'] ?? 'مشتری گرامی';
            $amountToman = getOrderAmountTomanPhp($ordObj);

            sendBaleMessage($activeToken, $cbChatId, "✅ فیش سفارش {$ordObj['trackingCode']} تایید شد و موجودی انبار کسر گردید.");

            // Notify customer if customer chat id is recorded
            $custChat = $ordObj['baleChatId'] ?? $ordObj['chatId'] ?? null;
            if ($custChat) {
                $custNotify =
                    "🎉 خریدار گرامی، پرداخت شما تأیید شد!\n\n" .
                    "✅ فیش واریزی سفارش {$ordObj['trackingCode']} توسط مدیریت تایید گردید.\n" .
                    "💰 مبلغ: " . number_format($amountToman) . " تومان\n" .
                    "📦 وضعیت مرسوله: در حال بسته‌بندی و ارسال پستی 🚚\n\n" .
                    "از حسن اعتماد شما به محصولات ارگانیک اونیوال صمیمانه سپاسگزاریم. 🌿🍯\n\n" .
                    "🔍 پیگیری لحظه‌ای سفارش:\n{$storeUrl}?track={$ordObj['trackingCode']}";
                $notifyToken = !empty($customerToken) ? $customerToken : $activeToken;
                sendBaleMessage($notifyToken, $custChat, $custNotify);
            }
            onival_log('order', 'receipt_approved', "Order {$ordObj['trackingCode']} confirmed by admin", [], $correlationId);
        } else {
            sendBaleMessage($activeToken, $cbChatId, "⚠️ خطا در تایید: " . ($txResult['error'] ?? 'خطای ناشناخته'));
        }

        echo json_encode(['ok' => true]);
        exit;
    }

    // Card-to-card instructions
    if (strpos($cbData, 'c2c_') === 0) {
        $c2cCode = substr($cbData, 4);
        $matched = findOrderByCodePhp($db['orders'] ?? [], $c2cCode);
        $amt = $matched ? getOrderAmountTomanPhp($matched) : 0;
        $c2cMsg =
            "💳 راهنمای پرداخت کارت‌به‌کارت سفارش {$c2cCode}:\n\n" .
            "▫️ شماره کارت: {$cardNumber}\n" .
            "▫️ به نام: {$cardHolder}\n" .
            "▫️ بانک: {$bankName}\n" .
            ($amt > 0 ? "▫️ مبلغ قابل واریز: " . number_format($amt) . " تومان\n\n" : "\n") .
            "📸 پس از انتقال وجه، لطفاً تصویر فیش واریزی را مستقیماً در همین گفتگو ارسال فرمایید تا سفارش بررسی و ارسال گردد.";
        sendBaleMessage($activeToken, $cbChatId, $c2cMsg);
        echo json_encode(['ok' => true]);
        exit;
    }
}

// ------------------------------------------------------------------------------
// 6. Handle Incoming Message Block
// ------------------------------------------------------------------------------
$message = $update['message'] ?? null;
if (!$message) {
    echo json_encode(['ok' => true, 'note' => 'No message block']);
    exit;
}

$chatId = (string)($message['chat']['id'] ?? '');
$senderName = trim(($message['from']['first_name'] ?? '') . ' ' . ($message['from']['last_name'] ?? ''));
$text = trim($message['text'] ?? ($message['caption'] ?? ''));

$mainKeyboard = [
    'keyboard' => [
        [['text' => '🧾 استعلام و پرداخت فاکتور من']],
        [['text' => '🛍️ فروشگاه اونیوال'], ['text' => '📦 پیگیری سفارش']],
        [['text' => '💳 راهنمای روش‌های پرداخت'], ['text' => '📞 تماس با ما و پشتیبانی']]
    ],
    'resize_keyboard' => true,
    'one_time_keyboard' => false
];

// ------------------------------------------------------------------------------
// 6-A. Handle successful_payment (Wallet Payment Completed)
// ------------------------------------------------------------------------------
if (isset($message['successful_payment'])) {
    $sp = $message['successful_payment'];
    $orderPayload = $sp['invoice_payload'] ?? '';
    $cleanOrderCode = str_replace(['_', 'pay-', 'order-'], ['-', '', ''], $orderPayload);
    $paidRials = intval($sp['total_amount'] ?? 0);
    $balePaymentId = $sp['provider_payment_charge_id'] ?? $sp['telegram_payment_charge_id'] ?? ('BALE-' . time());

    $txRes = withDatabaseTransaction(function(&$dbRef) use ($cleanOrderCode, $paidRials, $balePaymentId, $chatId, $paymentMode) {
        $order = findOrderByCodePhp($dbRef['orders'] ?? [], $cleanOrderCode);
        if (!$order) {
            return ['ok' => false, 'error' => 'Order not found'];
        }

        $expectedToman = getOrderAmountTomanPhp($order);
        $expectedRials = round($expectedToman * 10);
        if ($expectedRials > 0 && $paidRials < $expectedRials) {
            return ['ok' => false, 'error' => 'Underpaid'];
        }

        // Idempotency check: if already paid, do not re-deduct
        if (($order['paymentStatus'] ?? '') === 'Paid') {
            return ['ok' => true, 'alreadyPaid' => true, 'order' => $order];
        }

        $invRes = deductOrderInventory($dbRef, $order);
        if (!$invRes['ok']) {
            return ['ok' => false, 'error' => $invRes['error']];
        }

        foreach ($dbRef['orders'] as &$ord) {
            if (($ord['trackingCode'] ?? '') === $order['trackingCode']) {
                $ord['status'] = 'Processing';
                $ord['paymentStatus'] = 'Paid';
                $ord['paymentMethod'] = 'bale_wallet';
                $ord['paymentMode'] = $paymentMode;
                $ord['balePaymentRef'] = $balePaymentId;
                $ord['baleChatId'] = $chatId;
                $ord['paidAt'] = date('c');
                $ord['inventoryDeducted'] = true;
                return ['ok' => true, 'order' => $ord];
            }
        }
        return ['ok' => false, 'error' => 'Update failed'];
    });

    if ($txRes['ok']) {
        $foundOrder = $txRes['order'];
        $orderFinalCode = $foundOrder['trackingCode'] ?? $cleanOrderCode;
        $orderFinalAmount = getOrderAmountTomanPhp($foundOrder);

        // 1. Send receipt to customer
        $custReceipt =
            "✅ پرداخت شما با موفقیت در کیف‌پول بله انجام شد!\n\n" .
            "📦 کد پیگیری سفارش: {$orderFinalCode}\n" .
            "💳 مبلغ پرداختی: " . number_format($orderFinalAmount) . " تومان\n" .
            "🔖 شناسه تراکنش: {$balePaymentId}\n\n" .
            "🌿 سفارش شما وارد فرآیند آماده‌سازی و ارسال گردید. از اعتماد شما صمیمانه سپاسگزاریم.";
        $custButtons = [
            'inline_keyboard' => [
                [['text' => '🌐 پیگیری لحظه‌ای در وب‌سایت', 'url' => "{$storeUrl}?track={$orderFinalCode}"]]
            ]
        ];
        sendBaleMessage($customerToken ?: $activeToken, $chatId, $custReceipt, $custButtons);

        // 2. Alert admin
        $adminNotifyToken = !empty($adminToken) ? $adminToken : $activeToken;
        $adminAlert =
            "🔔 سفارش جدید با موفقیت پرداخت شد!\n\n" .
            "📦 شماره سفارش: {$orderFinalCode}\n" .
            "💰 مبلغ: " . number_format($orderFinalAmount) . " تومان\n" .
            "💳 روش: درگاه کیف‌پول بله ({$paymentMode})\n" .
            "🔖 تراکنش: {$balePaymentId}\n" .
            "⏰ زمان: " . date('Y/m/d - H:i');
        sendBaleMessage($adminNotifyToken, $adminChatId, $adminAlert);
        onival_log('payment', 'successful_wallet_payment', "Payment finalized for {$orderFinalCode}", [], $correlationId);
    }

    echo json_encode(['ok' => true]);
    exit;
}

// ------------------------------------------------------------------------------
// 6-B. Handle Incoming Photo Receipt (Card-to-Card)
// ------------------------------------------------------------------------------
$hasPhoto = !empty($message['photo']) && is_array($message['photo']);
$hasDocImage = !empty($message['document']) && strpos($message['document']['mime_type'] ?? '', 'image') !== false;

if ($hasPhoto || $hasDocImage) {
    $fileId = '';
    if ($hasPhoto) {
        $arr = $message['photo'];
        $largest = end($arr);
        $fileId = $largest['file_id'] ?? '';
    } else {
        $fileId = $message['document']['file_id'] ?? '';
    }

    $extractedCode = extractOrderCodePhp($text);
    $matchedOrder = null;

    if ($extractedCode) {
        $matchedOrder = findOrderByCodePhp($db['orders'] ?? [], $extractedCode);
    }

    // Lookup by user chat if no code was given in caption
    if (!$matchedOrder && !empty($db['orders'])) {
        foreach ($db['orders'] as $ord) {
            if (($ord['paymentStatus'] ?? '') !== 'Paid') {
                if ((string)($ord['baleChatId'] ?? '') === $chatId || (string)($ord['chatId'] ?? '') === $chatId) {
                    $matchedOrder = $ord;
                    break;
                }
            }
        }
    }

    if (!$matchedOrder) {
        $noMatchMsg =
            "📸 تصویر فیش واریزی دریافت شد، اما کد رهگیری سفارش در متن پیام (کپشن) یافت نشد.\n\n" .
            "💡 لطفاً کد پیگیری سفارش خود (مانند ONV-ORD-XXX) را در کپشن فیش ارسالی یا به صورت پیام متنی ارسال فرمایید تا فیش شما به سفارش مربوطه الصاق شود.";
        sendBaleMessage($activeToken, $chatId, $noMatchMsg, $mainKeyboard);
        echo json_encode(['ok' => true]);
        exit;
    }

    $finalOrderCode = $matchedOrder['trackingCode'];

    withDatabaseTransaction(function(&$dbRef) use ($finalOrderCode, $fileId, $chatId) {
        foreach ($dbRef['orders'] as &$ord) {
            if (($ord['trackingCode'] ?? '') === $finalOrderCode) {
                $ord['receiptFileId'] = $fileId;
                $ord['baleChatId'] = $chatId;
                $ord['paymentMethod'] = 'card_to_card';
                $ord['paymentStatus'] = 'PendingVerification';
                $ord['receiptUploadedAt'] = date('c');
                break;
            }
        }
    });

    $amountToman = getOrderAmountTomanPhp($matchedOrder);

    // Customer acknowledgement
    $custThanks =
        "از خرید و اعتماد شما به محصولات ارگانیک اونیوال سپاسگزاریم! 🌿🍯\n\n" .
        "📸 تصویر فیش واریزی با موفقیت دریافت شد و در صف بررسی واحد مالی قرار گرفت.\n\n" .
        "🔖 کد پیگیری فاکتور: {$finalOrderCode}\n" .
        "💰 مبلغ فاکتور: " . number_format($amountToman) . " تومان\n" .
        "⏳ وضعیت: در انتظار تایید مدیریت\n\n" .
        "به محض بررسی فیش، پیام تایید نهایی برای شما ارسال خواهد شد.";
    sendBaleMessage($activeToken, $chatId, $custThanks, $mainKeyboard);

    // Forward to Admin
    $adminTokenToUse = !empty($adminToken) ? $adminToken : $activeToken;
    $adminCaption =
        "🔔 فیش واریز کارت‌به‌کارت جدید دریافت شد!\n\n" .
        "📦 شماره سفارش: {$finalOrderCode}\n" .
        "💰 مبلغ: " . number_format($amountToman) . " تومان\n" .
        "⏰ زمان: " . date('Y/m/d - H:i') . "\n\n" .
        "⚡ جهت تایید فیش روی دستور زیر کلیک فرمایید:\n" .
        "/confirm_{$finalOrderCode}";

    $adminButtons = [
        'inline_keyboard' => [
            [['text' => '✅ تایید فیش واریزی', 'callback_data' => "confirm_{$finalOrderCode}"]]
        ]
    ];

    $photoSend = sendBalePhoto($adminTokenToUse, $adminChatId, $fileId, $adminCaption, $adminButtons);
    if (empty($photoSend['ok'])) {
        sendBaleMessage($adminTokenToUse, $adminChatId, $adminCaption, $adminButtons);
    }

    onival_log('receipt', 'receipt_uploaded', "Receipt uploaded for {$finalOrderCode}", [], $correlationId);
    echo json_encode(['ok' => true]);
    exit;
}

// ------------------------------------------------------------------------------
// 6-C. Handle Text Messages & Deep Links
// ------------------------------------------------------------------------------
if ($scope === 'admin' && $chatId !== $adminChatId) {
    sendBaleMessage($activeToken, $chatId, "این ربات منحصراً جهت مدیریت سفارشات فروشگاه اونیوال می‌باشد.");
    echo json_encode(['ok' => true]);
    exit;
}

// Handle Admin text commands: /confirm_<trackingCode>
if (preg_match('/^\/(?:confirm_|approve_|تایید_)([A-Za-z0-9_-]+)/iu', $text, $m)) {
    if ($chatId !== $adminChatId) {
        sendBaleMessage($activeToken, $chatId, "⛔ دسترسی غیرمجاز.");
        echo json_encode(['ok' => true]);
        exit;
    }

    $codeToConfirm = trim($m[1]);
    $txResult = withDatabaseTransaction(function(&$dbRef) use ($codeToConfirm) {
        $order = findOrderByCodePhp($dbRef['orders'] ?? [], $codeToConfirm);
        if (!$order) {
            return ['ok' => false, 'error' => 'سفارش یافت نشد'];
        }
        foreach ($dbRef['orders'] as &$ord) {
            if (($ord['trackingCode'] ?? '') === $order['trackingCode']) {
                if (($ord['paymentStatus'] ?? '') === 'Paid') {
                    return ['ok' => true, 'alreadyPaid' => true, 'order' => $ord];
                }
                $invRes = deductOrderInventory($dbRef, $ord);
                if (!$invRes['ok']) {
                    return ['ok' => false, 'error' => $invRes['error']];
                }
                $ord['paymentStatus'] = 'Paid';
                $ord['status'] = 'Processing';
                $ord['approvedAt'] = date('c');
                return ['ok' => true, 'order' => $ord];
            }
        }
        return ['ok' => false, 'error' => 'خطا در ثبت'];
    });

    if ($txResult['ok']) {
        sendBaleMessage($activeToken, $chatId, "✅ سفارش {$codeToConfirm} با موفقیت تایید شد و موجودی انبار کسر گردید.");
    } else {
        sendBaleMessage($activeToken, $chatId, "⚠️ خطا: " . ($txResult['error'] ?? 'نامشخص'));
    }
    echo json_encode(['ok' => true]);
    exit;
}

// Deep Link /start pay_<trackingCode> or Order Lookup
$orderCode = extractOrderCodePhp($text);

if ($orderCode) {
    $order = findOrderByCodePhp($db['orders'] ?? [], $orderCode);
    if ($order) {
        $amountToman = getOrderAmountTomanPhp($order);
        $amountRials = round($amountToman * 10);
        $isPaid = (($order['paymentStatus'] ?? '') === 'Paid');

        if ($isPaid) {
            $paidMsg =
                "✅ وضعیت سفارش: پرداخت شده\n\n" .
                "📦 کد رهگیری: {$order['trackingCode']}\n" .
                "💰 مبلغ: " . number_format($amountToman) . " تومان\n" .
                "🚚 وضعیت مرسوله: " . (($order['status'] ?? '') === 'Completed' ? 'تحویل داده شده' : 'در حال آماده‌سازی و ارسال') . "\n\n" .
                "🔍 مشاهده در وب‌سایت: {$storeUrl}?track={$order['trackingCode']}";
            sendBaleMessage($activeToken, $chatId, $paidMsg, $mainKeyboard);
        } else {
            // Unpaid order: Offer Bale Wallet payment & Card-to-Card
            $invoiceTitle = 'سفارش ' . mb_substr($order['trackingCode'], 0, 20);
            $invoiceDesc = 'پرداخت امن فاکتور سفارش اونیوال با کیف‌پول بله';
            $payload = 'pay_' . $order['trackingCode'];

            $invoiceSent = false;
            if (!empty($walletToken)) {
                $prices = [['label' => 'مبلغ کل سفارش', 'amount' => (int)$amountRials]];
                $invRes = sendBaleInvoiceSafe($activeToken, $chatId, $invoiceTitle, $invoiceDesc, $payload, $walletToken, 'IRR', $prices, $paymentMode);
                $invoiceSent = !empty($invRes['ok']);
            }

            $orderInfoMsg =
                "🧾 فاکتور سفارش {$order['trackingCode']}\n\n" .
                "👤 مشتری: " . ($order['userFullName'] ?? $order['customerName'] ?? 'مشتری گرامی') . "\n" .
                "💰 مبلغ کل: " . number_format($amountToman) . " تومان\n" .
                "⏳ وضعیت: در انتظار پرداخت\n\n" .
                ($invoiceSent ? "💳 کارت پرداخت کیف‌پول بله در بالا صادر گردید.\n\n" : "") .
                "▫️ جهت پرداخت کارت به کارت:\n" .
                "شماره کارت: {$cardNumber}\n" .
                "به نام: {$cardHolder} ({$bankName})\n\n" .
                "📸 پس از واریز، تصویر فیش را در همین گفتگو ارسال فرمایید.";

            $inlineBtns = [
                'inline_keyboard' => [
                    [['text' => '💳 راهنمای کارت به کارت', 'callback_data' => "c2c_{$order['trackingCode']}"]],
                    [['text' => '🌐 مشاهده فاکتور در وب‌سایت', 'url' => "{$storeUrl}?track={$order['trackingCode']}"]]
                ]
            ];
            sendBaleMessage($activeToken, $chatId, $orderInfoMsg, $inlineBtns);
        }
        echo json_encode(['ok' => true]);
        exit;
    } else {
        $notFoundMsg = "❌ سفارشی با کد پیگیری «{$orderCode}» در سیستم یافت نشد.\nلطفاً کد رهگیری فاکتور خود را با دقت بررسی فرمایید.";
        sendBaleMessage($activeToken, $chatId, $notFoundMsg, $mainKeyboard);
        echo json_encode(['ok' => true]);
        exit;
    }
}

// Menu button responses
if (strpos($text, 'فروشگاه') !== false) {
    sendBaleMessage($activeToken, $chatId, "🛍️ به فروشگاه تخصصی محصولات ارگانیک اونیوال خوش آمدید:\n{$storeUrl}", $mainKeyboard);
    echo json_encode(['ok' => true]);
    exit;
}

if (strpos($text, 'تماس') !== false || strpos($text, 'پشتیبانی') !== false) {
    sendBaleMessage($activeToken, $chatId, "📞 پشتیبانی اونیوال:\nتلفن: ۰۲۱-۱۲۳۴۵۶۷۸\nوب‌سایت: {$storeUrl}", $mainKeyboard);
    echo json_encode(['ok' => true]);
    exit;
}

if (strpos($text, 'روش‌های پرداخت') !== false || strpos($text, 'کارت به کارت') !== false) {
    $infoPay =
        "💳 روش‌های پرداخت در فروشگاه اونیوال:\n\n" .
        "۱. پرداخت با کیف‌پول بله (آنلاین و آنی با رمز دوم پویا)\n" .
        "۲. پرداخت کارت به کارت به شماره زیر و ارسال فیش در همین ربات:\n" .
        "▫️ کارت: {$cardNumber}\n" .
        "▫️ به نام: {$cardHolder}\n" .
        "▫️ بانک: {$bankName}";
    sendBaleMessage($activeToken, $chatId, $infoPay, $mainKeyboard);
    echo json_encode(['ok' => true]);
    exit;
}

if (strpos($text, 'استعلام') !== false || strpos($text, 'پیگیری') !== false) {
    sendBaleMessage($activeToken, $chatId, "🔍 لطفاً کد پیگیری سفارش خود (مانند ONV-ORD-XXX یا شماره سفارش) را ارسال فرمایید:", $mainKeyboard);
    echo json_encode(['ok' => true]);
    exit;
}

// Default Welcome message
$welcome =
    "به ربات رسمی فروشگاه تخصصی اونیوال (ONIVAL) خوش آمدید! 🍯🌿\n\n" .
    "از طریق دکمه‌های زیر می‌توانید سفارش‌های خود را استعلام کرده، با کیف‌پول بله یا کارت‌به‌کارت پرداخت کنید و وضعیت ارسال را پیگیری فرمایید.";
sendBaleMessage($activeToken, $chatId, $welcome, $mainKeyboard);

echo json_encode(['ok' => true]);
