<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/member/_guard.php';
require_once dirname(__DIR__) . '/includes/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/mailer.php';

$cancelRefundHelperCandidates = [
    __DIR__ . '/includes/cancel_refund_summary.php',
    dirname(__DIR__) . '/seller/includes/cancel_refund_summary.php',
];

foreach ($cancelRefundHelperCandidates as $cancelRefundHelperFile) {
    if (is_file($cancelRefundHelperFile)) {
        require_once $cancelRefundHelperFile;
        break;
    }
}

function e($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

if (!function_exists('seller_application_status_safe')) {
    function seller_application_status_safe(): string
    {
        if (function_exists('seller_application_status')) {
            return (string) seller_application_status();
        }

        return (string) ($_SESSION['user']['seller_application_status'] ?? '');
    }
}

if (!function_exists('seller_is_approved_safe')) {
    function seller_is_approved_safe(): bool
    {
        if (function_exists('is_active_seller')) {
            return is_active_seller();
        }

        return (string) ($_SESSION['user']['role'] ?? '') === 'seller'
            && seller_application_status_safe() === 'approved';
    }
}

function seller_apply_csrf_token(): string
{
    if (empty($_SESSION['seller_apply_csrf_token'])) {
        $_SESSION['seller_apply_csrf_token'] = bin2hex(random_bytes(32));
    }
    return (string)$_SESSION['seller_apply_csrf_token'];
}

function seller_apply_verify_csrf(?string $token): bool
{
    return isset($_SESSION['seller_apply_csrf_token'])
        && is_string($token)
        && hash_equals($_SESSION['seller_apply_csrf_token'], $token);
}

function seller_apply_table_exists(PDO $pdo, string $tableName): bool
{
    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = :table_name");
        $stmt->execute([':table_name' => $tableName]);
        return (int)$stmt->fetchColumn() > 0;
    } catch (Throwable $e) {
        return false;
    }
}

function seller_apply_client_ip(): string
{
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
        if (!empty($_SERVER[$key])) {
            $value = trim((string)$_SERVER[$key]);
            if ($key === 'HTTP_X_FORWARDED_FOR' && strpos($value, ',') !== false) {
                $parts = explode(',', $value);
                $value = trim((string)$parts[0]);
            }
            if ($value !== '') {
                return substr($value, 0, 45);
            }
        }
    }
    return '';
}

function seller_apply_user_agent(): string
{
    return isset($_SERVER['HTTP_USER_AGENT']) ? substr(trim((string)$_SERVER['HTTP_USER_AGENT']), 0, 500) : '';
}

function seller_apply_session_id_safe(): string
{
    $sessionId = session_id();
    return $sessionId !== '' ? substr($sessionId, 0, 128) : '';
}

function seller_apply_digits_only(string $value): string
{
    return preg_replace('/\D+/', '', $value) ?? '';
}

function seller_apply_value_or_null(string $value): ?string
{
    $value = trim($value);
    return $value !== '' ? $value : null;
}

function seller_apply_upload_error_message(int $code): string
{
    switch ($code) {
        case UPLOAD_ERR_INI_SIZE:
        case UPLOAD_ERR_FORM_SIZE: return 'The uploaded file is too large.';
        case UPLOAD_ERR_PARTIAL: return 'The uploaded file was only partially uploaded.';
        case UPLOAD_ERR_NO_FILE: return 'No file was uploaded.';
        case UPLOAD_ERR_NO_TMP_DIR: return 'Server temporary folder is missing.';
        case UPLOAD_ERR_CANT_WRITE: return 'The server could not write the uploaded file.';
        case UPLOAD_ERR_EXTENSION: return 'A PHP extension stopped the file upload.';
        default: return 'Unknown upload error.';
    }
}

function seller_apply_validate_upload(string $fieldName, string $label, bool $required, array $allowedExtensions, array $allowedMimeTypes, int $maxBytes, array &$errors): ?array
{
    if (!isset($_FILES[$fieldName]) || !is_array($_FILES[$fieldName])) {
        if ($required) {
            $errors[] = 'Please upload ' . $label . '.';
        }
        return null;
    }

    $file = $_FILES[$fieldName];
    $errorCode = isset($file['error']) ? (int)$file['error'] : UPLOAD_ERR_NO_FILE;

    if ($errorCode === UPLOAD_ERR_NO_FILE) {
        if ($required) {
            $errors[] = 'Please upload ' . $label . '.';
        }
        return null;
    }

    if ($errorCode !== UPLOAD_ERR_OK) {
        $errors[] = $label . ': ' . seller_apply_upload_error_message($errorCode);
        return null;
    }

    $tmpName = (string)($file['tmp_name'] ?? '');
    $originalName = trim((string)($file['name'] ?? ''));
    $size = (int)($file['size'] ?? 0);

    if ($tmpName === '' || !is_uploaded_file($tmpName)) {
        $errors[] = $label . ': invalid uploaded file.';
        return null;
    }
    if ($size <= 0) {
        $errors[] = $label . ': empty file is not allowed.';
        return null;
    }
    if ($size > $maxBytes) {
        $errors[] = $label . ': file is too large. Maximum allowed size is ' . number_format($maxBytes / 1024 / 1024, 0) . ' MB.';
        return null;
    }

    $extension = strtolower((string)pathinfo($originalName, PATHINFO_EXTENSION));
    if ($extension === '' || !in_array($extension, $allowedExtensions, true)) {
        $errors[] = $label . ': invalid file extension.';
        return null;
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = $finfo ? (string)finfo_file($finfo, $tmpName) : '';
    if ($finfo) {
        finfo_close($finfo);
    }

    if ($mimeType === '' || !in_array($mimeType, $allowedMimeTypes, true)) {
        $errors[] = $label . ': invalid file type.';
        return null;
    }

    return [
        'field_name'    => $fieldName,
        'label'         => $label,
        'tmp_name'      => $tmpName,
        'original_name' => $originalName !== '' ? $originalName : ($fieldName . '.' . $extension),
        'extension'     => $extension,
        'mime_type'     => $mimeType,
        'file_size'     => $size,
    ];
}

function seller_apply_ensure_directory(string $absoluteDirectory): void
{
    if (is_dir($absoluteDirectory)) {
        return;
    }
    if (!mkdir($absoluteDirectory, 0755, true) && !is_dir($absoluteDirectory)) {
        throw new RuntimeException('Unable to create upload directory: ' . $absoluteDirectory);
    }
}

function seller_apply_store_upload(array $upload, string $rootAbsoluteDir, string $relativePrefix): array
{
    $subFolder = date('Y/m');
    $targetDirectory = rtrim($rootAbsoluteDir, '/\\') . DIRECTORY_SEPARATOR . str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $subFolder);
    seller_apply_ensure_directory($targetDirectory);

    $safeFilename = date('YmdHis') . '_' . bin2hex(random_bytes(8)) . '.' . $upload['extension'];
    $absolutePath = $targetDirectory . DIRECTORY_SEPARATOR . $safeFilename;

    if (!move_uploaded_file($upload['tmp_name'], $absolutePath)) {
        throw new RuntimeException('Failed to move uploaded file for ' . $upload['label'] . '.');
    }

    $hash = hash_file('sha256', $absolutePath);
    $relativePath = trim($relativePrefix, '/\\') . '/' . str_replace('\\', '/', $subFolder) . '/' . $safeFilename;

    return [
        'document_label'  => $upload['label'],
        'storage_path'    => $relativePath,
        'absolute_path'   => $absolutePath,
        'original_name'   => $upload['original_name'],
        'mime_type'       => $upload['mime_type'],
        'file_size_bytes' => $upload['file_size'],
        'file_hash'       => $hash !== false ? $hash : null,
    ];
}

function seller_apply_cleanup_files(array $absolutePaths): void
{
    foreach ($absolutePaths as $absolutePath) {
        if (is_string($absolutePath) && $absolutePath !== '' && is_file($absolutePath)) {
            @unlink($absolutePath);
        }
    }
}

function seller_apply_insert_document(PDO $pdo, int $applicationId, string $documentType, ?array $storedFile, string $now): void
{
    if ($storedFile === null) {
        return;
    }

    $stmt = $pdo->prepare("INSERT INTO seller_documents (application_id, document_type, document_label, storage_path, original_name, mime_type, file_size_bytes, uploaded_at) VALUES (:application_id, :document_type, :document_label, :storage_path, :original_name, :mime_type, :file_size_bytes, :uploaded_at)");
    $stmt->execute([
        ':application_id'  => $applicationId,
        ':document_type'   => $documentType,
        ':document_label'  => $storedFile['document_label'],
        ':storage_path'    => $storedFile['storage_path'],
        ':original_name'   => $storedFile['original_name'],
        ':mime_type'       => $storedFile['mime_type'],
        ':file_size_bytes' => $storedFile['file_size_bytes'],
        ':uploaded_at'     => $now,
    ]);
}

function seller_apply_insert_consent_log(PDO $pdo, int $userId, int $applicationId, string $documentType, string $documentVersion, ?string $documentHash, string $eventType, string $ipAddress, string $userAgent, string $sessionId, string $now): void
{
    $stmt = $pdo->prepare("INSERT INTO seller_consent_logs (user_id, application_id, document_type, document_version, document_hash, event_type, is_accepted, ip_address, user_agent, session_id, created_at) VALUES (:user_id, :application_id, :document_type, :document_version, :document_hash, :event_type, 1, :ip_address, :user_agent, :session_id, :created_at)");
    $stmt->execute([
        ':user_id'          => $userId,
        ':application_id'   => $applicationId,
        ':document_type'    => $documentType,
        ':document_version' => $documentVersion,
        ':document_hash'    => $documentHash,
        ':event_type'       => $eventType,
        ':ip_address'       => $ipAddress !== '' ? $ipAddress : null,
        ':user_agent'       => $userAgent !== '' ? $userAgent : null,
        ':session_id'       => $sessionId !== '' ? $sessionId : null,
        ':created_at'       => $now,
    ]);
}

function seller_apply_insert_status_history(PDO $pdo, int $applicationId, int $changedBy, string $oldStatus, string $newStatus, string $note, string $now): void
{
    $stmt = $pdo->prepare("INSERT INTO seller_application_status_history (application_id, old_status, new_status, changed_by, note, created_at) VALUES (:application_id, :old_status, :new_status, :changed_by, :note, :created_at)");
    $stmt->execute([
        ':application_id' => $applicationId,
        ':old_status'     => $oldStatus !== '' ? $oldStatus : null,
        ':new_status'     => $newStatus,
        ':changed_by'     => $changedBy,
        ':note'           => $note,
        ':created_at'     => $now,
    ]);
}

function seller_apply_format_datetime(string $datetime): string
{
    $ts = strtotime($datetime);
    return $ts ? date('Y-m-d H:i:s', $ts) : $datetime;
}

function seller_apply_build_absolute_url(string $path): string
{
    $base = defined('APP_URL') ? rtrim((string)APP_URL, '/') : 'https://www.bettavaro.com';
    if ($path === '') {
        return $base;
    }
    if (strpos($path, 'http://') === 0 || strpos($path, 'https://') === 0) {
        return $path;
    }
    return $base . '/' . ltrim($path, '/');
}

function seller_apply_seller_email_body(string $memberName, string $memberEmail, string $submittedAt, string $applicationStatus, string $termsVersion, string $privacyVersion, string $sellerTermsUrlEn, string $sellerTermsUrlTh, string $privacyPolicyUrlEn, string $privacyPolicyUrlTh, string $siteName): string
{
    $name = trim($memberName) !== '' ? $memberName : 'Seller';
    return "Hello {$name},\n\n" .
        "Your seller application has been submitted successfully to {$siteName}.\n\n" .
        "Application details:\n" .
        "- Email: {$memberEmail}\n" .
        "- Submitted at: {$submittedAt}\n" .
        "- Current status: {$applicationStatus}\n" .
        "- Seller Terms version accepted: {$termsVersion}\n" .
        "- Privacy Policy version accepted: {$privacyVersion}\n\n" .
        "Legal document links:\n" .
        "- Seller Terms (EN): {$sellerTermsUrlEn}\n" .
        "- Seller Terms (TH): {$sellerTermsUrlTh}\n" .
        "- Privacy Policy (EN): {$privacyPolicyUrlEn}\n" .
        "- Privacy Policy (TH): {$privacyPolicyUrlTh}\n\n" .
        "Our team will review your application and contact you if additional information is needed.\n\n" .
        "Please keep this email for your records.\n\n" .
        "Regards,\n{$siteName} Team\n";
}

function seller_apply_admin_email_body(string $memberName, string $memberEmail, int $applicationId, string $submittedAt, array $form, string $siteName): string
{
    return "New seller application submitted on {$siteName}\n\n" .
        "Application summary:\n" .
        "- Application ID: {$applicationId}\n" .
        "- Member name: {$memberName}\n" .
        "- Member email: {$memberEmail}\n" .
        "- Submitted at: {$submittedAt}\n" .
        "- Farm name: " . $form['farm_name'] . "\n" .
        "- Farm phone: " . $form['farm_phone'] . "\n" .
        "- Province: " . $form['farm_province'] . "\n" .
        "- District: " . $form['farm_district'] . "\n" .
        "- Subdistrict: " . $form['farm_subdistrict'] . "\n" .
        "- Postal code: " . $form['farm_postal_code'] . "\n" .
        "- Certificate name: " . $form['certificate_name'] . "\n" .
        "- Certificate number: " . $form['certificate_number'] . "\n" .
        "- Terms version: " . $form['accepted_terms_version'] . "\n" .
        "- Privacy version: " . $form['accepted_privacy_version'] . "\n\n" .
        "Please review this application in the admin panel.\n";
}

if (!function_exists('seller_session_write_user')) {
    function seller_session_write_user(array $user): void
    {
        $firstName = (string) ($user['first_name'] ?? '');
        $lastName = (string) ($user['last_name'] ?? '');
        $email = (string) ($user['email'] ?? '');
        $role = (string) ($user['role'] ?? 'user');
        $sellerStatus = isset($user['seller_application_status']) ? (string) $user['seller_application_status'] : '';
        $fullName = trim($firstName . ' ' . $lastName);

        $_SESSION['user'] = [
            'id' => (int) ($user['id'] ?? 0),
            'first_name' => $firstName,
            'last_name' => $lastName,
            'email' => $email,
            'role' => $role,
            'seller_application_status' => $sellerStatus !== '' ? $sellerStatus : null,
        ];

        $_SESSION['user_id'] = (int) ($user['id'] ?? 0);
        $_SESSION['member_id'] = (int) ($user['id'] ?? 0);
        $_SESSION['member_email'] = $email;
        $_SESSION['member_role'] = $role;
        $_SESSION['user_email'] = $email;
        $_SESSION['user_role'] = $role;
        $_SESSION['user_first_name'] = $firstName;
        $_SESSION['user_last_name'] = $lastName;
        $_SESSION['user_name'] = $fullName !== '' ? $fullName : $email;
        $_SESSION['seller_application_status'] = $sellerStatus;
    }
}

$userId = member_user_id();
$role   = member_user_role();
$sessionSellerStatus = seller_application_status_safe();

$flashSuccess = $_SESSION['seller_apply_success'] ?? '';
unset($_SESSION['seller_apply_success']);

$errors = [];
$infoMessage = '';

$sellerTermsUrl      = '/legal/seller-terms.php?lang=en';
$sellerTermsUrlTh    = '/legal/seller-terms.php?lang=th';
$privacyPolicyUrl    = '/legal/privacy-policy.php?lang=en';
$privacyPolicyUrlTh  = '/legal/privacy-policy.php?lang=th';
$termsVersionDefault   = 'seller-terms-v1.0';
$privacyVersionDefault = 'privacy-policy-v1.0';
$termsDocumentHash = '';
$privacyDocumentHash = '';
$privateUploadRoot = dirname(dirname(__DIR__)) . '/public_html/uploads/seller_applications';
$relativeUploadPrefix = 'seller_applications';
$mailerCfg = bv_mailer_config();
$siteName = (string)($mailerCfg['site_name'] ?? 'Bettavaro');
$mailFromEmail = (string)($mailerCfg['from_email'] ?? 'support@bettavaro.com');
$mailFromName  = (string)($mailerCfg['from_name'] ?? 'Bettavaro Support');
$adminNotificationEmails = ['admin@bettavaro.com'];

$form = [
    'farm_name' => '', 'farm_address_line1' => '', 'farm_address_line2' => '', 'farm_road' => '', 'farm_subdistrict' => '',
    'farm_district' => '', 'farm_province' => '', 'farm_postal_code' => '', 'farm_phone' => '', 'certificate_name' => '',
    'certificate_number' => '', 'id_card_number' => '', 'bank_name' => '', 'bank_branch_name' => '', 'bank_account_name' => '',
    'bank_account_number' => '', 'map_place_name' => '', 'map_lat' => '', 'map_lng' => '',
    'accepted_terms_version' => $termsVersionDefault, 'accepted_privacy_version' => $privacyVersionDefault,
    'accept_terms' => '', 'accept_privacy' => '', 'terms_modal_confirmed' => '', 'privacy_modal_confirmed' => '',
];

$userStmt = $pdo->prepare("SELECT id, first_name, last_name, email, role, account_status FROM users WHERE id = :id LIMIT 1");
$userStmt->execute([':id' => $userId]);
$user = $userStmt->fetch(PDO::FETCH_ASSOC);
if (!$user) {
    http_response_code(404);
    exit('Member not found.');
}

$fullNameDefault = trim((string)($user['first_name'] ?? '') . ' ' . (string)($user['last_name'] ?? ''));
$memberEmail = trim((string)($user['email'] ?? ''));

$existingApplication = null;
if (seller_apply_table_exists($pdo, 'seller_applications')) {
    try {
        $check = $pdo->prepare("SELECT * FROM seller_applications WHERE user_id = :user_id ORDER BY id DESC LIMIT 1");
        $check->execute([':user_id' => $userId]);
        $existingApplication = $check->fetch(PDO::FETCH_ASSOC) ?: null;
    } catch (Throwable $e) {
        $existingApplication = null;
    }
}

$existingStatus = (string)($existingApplication['application_status'] ?? $sessionSellerStatus);
$existingApplicationId = (int)($existingApplication['id'] ?? 0);

if ($role === 'admin') {
    $infoMessage = 'This account already has admin access. Seller application is not needed.';
}
if (seller_is_approved_safe()) {
    $infoMessage = 'This account is already approved as a seller. Use the member dashboard as your seller base for now.';
}
if ($existingApplication && $existingStatus !== 'rejected') {
    $infoMessage = 'You already have a seller application in the system.';
}

$canSubmit = !$role || !in_array($role, ['admin'], true);
$canSubmit = $canSubmit && !seller_is_approved_safe();
$canSubmit = $canSubmit && (!$existingApplication || $existingStatus === 'rejected');

$offerFeatureAvailable = false;
$offerStats = [
    'total' => 0,
    'open' => 0,
    'needs_reply' => 0,
    'accepted_or_ready' => 0,
    'completed' => 0,
];
$recentOffers = [];

$cancelRefundSummary = [
    'pending_cancel_count' => 0,
    'pending_refund_count' => 0,
    'refund_ready_count' => 0,
    'completed_refund_count' => 0,
    'total_open_requests' => 0,
];
$cancelRefundRecent = [];
$cancelRefundOrderListUrl = '';

if (function_exists('seller_cancel_refund_get_summary') && function_exists('seller_cancel_refund_get_recent_requests') && seller_is_approved_safe()) {
    try {
        $cancelRefundSummary = seller_cancel_refund_get_summary($userId);
        $cancelRefundRecent = seller_cancel_refund_get_recent_requests($userId, 5);

        foreach (['/seller/orders.php', '/member/orders.php'] as $route) {
            $absoluteCandidate = dirname(__DIR__) . $route;
            if (is_file($absoluteCandidate)) {
                $cancelRefundOrderListUrl = $route;
                break;
            }
            $localCandidate = __DIR__ . $route;
            if (is_file($localCandidate)) {
                $cancelRefundOrderListUrl = $route;
                break;
            }
        }
    } catch (Throwable $e) {
        $cancelRefundSummary = [
            'pending_cancel_count' => 0,
            'pending_refund_count' => 0,
            'refund_ready_count' => 0,
            'completed_refund_count' => 0,
            'total_open_requests' => 0,
        ];
        $cancelRefundRecent = [];
    }
}

$listingOffersExists = seller_apply_table_exists($pdo, 'listing_offers');
if ($listingOffersExists && $userId > 0) {
    $offerFeatureAvailable = true;

    try {
        $offerStmt = $pdo->prepare("
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN o.status = 'open' THEN 1 ELSE 0 END) AS open_count,
                SUM(
                    CASE
                        WHEN o.status = 'open'
                         AND lm.sender_role = 'buyer'
                        THEN 1 ELSE 0
                    END
                ) AS needs_reply_count,
                SUM(CASE WHEN o.status IN ('seller_accepted', 'buyer_checkout_ready') THEN 1 ELSE 0 END) AS accepted_ready_count,
                SUM(CASE WHEN o.status = 'completed' THEN 1 ELSE 0 END) AS completed_count
            FROM listing_offers o
            LEFT JOIN (
                SELECT m1.offer_id, m1.sender_role
                FROM listing_offer_messages m1
                INNER JOIN (
                    SELECT offer_id, MAX(id) AS max_id
                    FROM listing_offer_messages
                    GROUP BY offer_id
                ) lastm
                    ON lastm.offer_id = m1.offer_id
                   AND lastm.max_id = m1.id
            ) lm
                ON lm.offer_id = o.id
            WHERE o.seller_user_id = :seller_user_id
        ");
        $offerStmt->execute([':seller_user_id' => $userId]);
        $offerRow = $offerStmt->fetch(PDO::FETCH_ASSOC) ?: [];

        $offerStats['total'] = (int)($offerRow['total'] ?? 0);
        $offerStats['open'] = (int)($offerRow['open_count'] ?? 0);
        $offerStats['needs_reply'] = (int)($offerRow['needs_reply_count'] ?? 0);
        $offerStats['accepted_or_ready'] = (int)($offerRow['accepted_ready_count'] ?? 0);
        $offerStats['completed'] = (int)($offerRow['completed_count'] ?? 0);
    } catch (Throwable $e) {
        error_log('seller apply offer stats load failed: ' . $e->getMessage());
    }

    try {
        $offerListStmt = $pdo->prepare("
            SELECT
                o.id,
                o.listing_id,
                o.status,
                o.currency,
                o.latest_offer_price,
                o.agreed_price,
                o.updated_at,
                l.title AS listing_title,
                l.slug,
                lm.sender_role AS last_sender_role,
                1 AS needs_reply
            FROM listing_offers o
            LEFT JOIN listings l
                ON l.id = o.listing_id
            INNER JOIN (
                SELECT m1.offer_id, m1.sender_role
                FROM listing_offer_messages m1
                INNER JOIN (
                    SELECT offer_id, MAX(id) AS max_id
                    FROM listing_offer_messages
                    GROUP BY offer_id
                ) lastm
                    ON lastm.offer_id = m1.offer_id
                   AND lastm.max_id = m1.id
            ) lm
                ON lm.offer_id = o.id
            WHERE o.seller_user_id = :seller_user_id
              AND o.status = 'open'
              AND lm.sender_role = 'buyer'
            ORDER BY o.updated_at DESC, o.id DESC
            LIMIT 3
        ");
        $offerListStmt->execute([':seller_user_id' => $userId]);
        $recentOffers = $offerListStmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
    } catch (Throwable $e) {
        error_log('seller apply recent offers load failed: ' . $e->getMessage());
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    foreach (array_keys($form) as $key) {
        $form[$key] = trim((string)($_POST[$key] ?? ''));
    }

    if (!$canSubmit) {
        $errors[] = 'This account cannot submit a new seller application right now.';
    }

    $csrfToken = (string)($_POST['csrf_token'] ?? '');
    if (!seller_apply_verify_csrf($csrfToken)) {
        $errors[] = 'Session security check failed. Please refresh the page and try again.';
    }
    if (!seller_apply_table_exists($pdo, 'seller_applications')) {
        $errors[] = 'Seller application table is not ready yet.';
    }
    if (!seller_apply_table_exists($pdo, 'seller_documents')) {
        $errors[] = 'Seller documents table is not ready yet.';
    }
    if (!seller_apply_table_exists($pdo, 'seller_consent_logs')) {
        $errors[] = 'Seller consent logs table is not ready yet.';
    }
    if (!seller_apply_table_exists($pdo, 'seller_application_status_history')) {
        $errors[] = 'Seller application status history table is not ready yet.';
    }

    if ($form['farm_name'] === '') { $errors[] = 'Please enter your farm name.'; }
    if ($form['farm_address_line1'] === '') { $errors[] = 'Please enter address line 1.'; }
    if ($form['farm_subdistrict'] === '') { $errors[] = 'Please enter subdistrict.'; }
    if ($form['farm_district'] === '') { $errors[] = 'Please enter district.'; }
    if ($form['farm_province'] === '') { $errors[] = 'Please enter province.'; }
    if ($form['farm_postal_code'] === '') { $errors[] = 'Please enter postal code.'; }
    elseif (!preg_match('/^\d{5}$/', $form['farm_postal_code'])) { $errors[] = 'Postal code must be 5 digits.'; }
    if ($form['farm_phone'] === '') { $errors[] = 'Please enter farm phone.'; }
    elseif (strlen(seller_apply_digits_only($form['farm_phone'])) < 8) { $errors[] = 'Farm phone number looks incomplete.'; }
    if ($form['id_card_number'] === '') { $errors[] = 'Please enter ID card number.'; }
    elseif (!preg_match('/^\d{13}$/', seller_apply_digits_only($form['id_card_number']))) { $errors[] = 'ID card number must be 13 digits.'; }
    if ($form['bank_name'] === '') { $errors[] = 'Please enter bank name.'; }
    if ($form['bank_branch_name'] === '') { $errors[] = 'Please enter bank branch name.'; }
    if ($form['bank_account_name'] === '') { $errors[] = 'Please enter bank account name.'; }
    if ($form['bank_account_number'] === '') { $errors[] = 'Please enter bank account number.'; }
    elseif (strlen(seller_apply_digits_only($form['bank_account_number'])) < 6) { $errors[] = 'Bank account number looks incomplete.'; }
    if ($form['accepted_terms_version'] === '') { $errors[] = 'Seller terms version is missing.'; }
    if ($form['accepted_privacy_version'] === '') { $errors[] = 'Privacy policy version is missing.'; }
    if ($form['accept_terms'] !== '1') { $errors[] = 'You must accept the seller terms and conditions.'; }
    if ($form['accept_privacy'] !== '1') { $errors[] = 'You must accept the privacy policy.'; }
    if ($form['terms_modal_confirmed'] !== '1') { $errors[] = 'Please confirm the seller terms in the popup before submitting.'; }
    if ($form['privacy_modal_confirmed'] !== '1') { $errors[] = 'Please confirm the privacy policy in the popup before submitting.'; }
    if ($form['map_lat'] !== '' && (!is_numeric($form['map_lat']) || (float)$form['map_lat'] < -90 || (float)$form['map_lat'] > 90)) { $errors[] = 'Map latitude must be between -90 and 90.'; }
    if ($form['map_lng'] !== '' && (!is_numeric($form['map_lng']) || (float)$form['map_lng'] < -180 || (float)$form['map_lng'] > 180)) { $errors[] = 'Map longitude must be between -180 and 180.'; }
    if ($memberEmail === '' || !filter_var($memberEmail, FILTER_VALIDATE_EMAIL)) { $errors[] = 'Your member email address is invalid or missing.'; }

    $uploadMaxBytes = 8 * 1024 * 1024;
    $farmLogoUpload = seller_apply_validate_upload('farm_logo_file', 'Farm logo', false, ['jpg', 'jpeg', 'png', 'webp'], ['image/jpeg', 'image/png', 'image/webp'], $uploadMaxBytes, $errors);
    $certificateUpload = seller_apply_validate_upload('certificate_image_file', 'Government farmer certificate', false, ['jpg', 'jpeg', 'png', 'webp', 'pdf'], ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'], $uploadMaxBytes, $errors);
    $idCardFrontUpload = seller_apply_validate_upload('id_card_front_file', 'ID card picture', true, ['jpg', 'jpeg', 'png', 'webp'], ['image/jpeg', 'image/png', 'image/webp'], $uploadMaxBytes, $errors);
    $bankBookUpload = seller_apply_validate_upload('bank_book_image_file', 'Bank book image', false, ['jpg', 'jpeg', 'png', 'webp', 'pdf'], ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'], $uploadMaxBytes, $errors);

    if (empty($errors)) {
        $movedFiles = [];
        try {
            $now = date('Y-m-d H:i:s');
            $submittedAt = $now;
            $ip = seller_apply_client_ip();
            $userAgent = seller_apply_user_agent();
            $sessionId = seller_apply_session_id_safe();

            $storedFarmLogo = $farmLogoUpload ? seller_apply_store_upload($farmLogoUpload, $privateUploadRoot, $relativeUploadPrefix) : null;
            if ($storedFarmLogo) { $movedFiles[] = $storedFarmLogo['absolute_path']; }
            $storedCertificate = $certificateUpload ? seller_apply_store_upload($certificateUpload, $privateUploadRoot, $relativeUploadPrefix) : null;
            if ($storedCertificate) { $movedFiles[] = $storedCertificate['absolute_path']; }
            $storedIdCardFront = $idCardFrontUpload ? seller_apply_store_upload($idCardFrontUpload, $privateUploadRoot, $relativeUploadPrefix) : null;
            if ($storedIdCardFront) { $movedFiles[] = $storedIdCardFront['absolute_path']; }
            $storedBankBook = $bankBookUpload ? seller_apply_store_upload($bankBookUpload, $privateUploadRoot, $relativeUploadPrefix) : null;
            if ($storedBankBook) { $movedFiles[] = $storedBankBook['absolute_path']; }

            if ($storedIdCardFront === null) {
                throw new RuntimeException('Missing required files after upload validation.');
            }

            $pdo->beginTransaction();
            $newStatus = 'submitted';

            if ($existingApplication && $existingStatus === 'rejected') {
                $stmt = $pdo->prepare("UPDATE seller_applications SET application_status = :application_status, farm_name = :farm_name, farm_logo_path = :farm_logo_path, farm_address_line1 = :farm_address_line1, farm_address_line2 = :farm_address_line2, farm_road = :farm_road, farm_subdistrict = :farm_subdistrict, farm_district = :farm_district, farm_province = :farm_province, farm_postal_code = :farm_postal_code, farm_phone = :farm_phone, certificate_name = :certificate_name, certificate_number = :certificate_number, certificate_image_path = :certificate_image_path, id_card_number = :id_card_number, id_card_front_path = :id_card_front_path, bank_name = :bank_name, bank_branch_name = :bank_branch_name, bank_account_name = :bank_account_name, bank_account_number = :bank_account_number, bank_book_image_path = :bank_book_image_path, accepted_terms_version = :accepted_terms_version, accepted_terms_at = :accepted_terms_at, accepted_terms_ip = :accepted_terms_ip, accepted_privacy_version = :accepted_privacy_version, accepted_privacy_at = :accepted_privacy_at, accepted_privacy_ip = :accepted_privacy_ip, map_place_name = :map_place_name, map_lat = :map_lat, map_lng = :map_lng, submitted_at = :submitted_at, updated_at = :updated_at WHERE id = :id LIMIT 1");
                $stmt->execute([
                    ':application_status' => $newStatus,
                    ':farm_name' => $form['farm_name'],
                    ':farm_logo_path' => $storedFarmLogo ? $storedFarmLogo['storage_path'] : null,
                    ':farm_address_line1' => $form['farm_address_line1'],
                    ':farm_address_line2' => seller_apply_value_or_null($form['farm_address_line2']),
                    ':farm_road' => seller_apply_value_or_null($form['farm_road']),
                    ':farm_subdistrict' => $form['farm_subdistrict'],
                    ':farm_district' => $form['farm_district'],
                    ':farm_province' => $form['farm_province'],
                    ':farm_postal_code' => $form['farm_postal_code'],
                    ':farm_phone' => $form['farm_phone'],
                    ':certificate_name' => seller_apply_value_or_null($form['certificate_name']),
                    ':certificate_number' => seller_apply_value_or_null($form['certificate_number']),
                    ':certificate_image_path' => $storedCertificate ? $storedCertificate['storage_path'] : null,
                    ':id_card_number' => seller_apply_digits_only($form['id_card_number']),
                    ':id_card_front_path' => $storedIdCardFront['storage_path'],
                    ':bank_name' => $form['bank_name'],
                    ':bank_branch_name' => $form['bank_branch_name'],
                    ':bank_account_name' => $form['bank_account_name'],
                    ':bank_account_number' => seller_apply_digits_only($form['bank_account_number']),
                    ':bank_book_image_path' => $storedBankBook ? $storedBankBook['storage_path'] : null,
                    ':accepted_terms_version' => $form['accepted_terms_version'],
                    ':accepted_terms_at' => $now,
                    ':accepted_terms_ip' => $ip !== '' ? $ip : null,
                    ':accepted_privacy_version' => $form['accepted_privacy_version'],
                    ':accepted_privacy_at' => $now,
                    ':accepted_privacy_ip' => $ip !== '' ? $ip : null,
                    ':map_place_name' => seller_apply_value_or_null($form['map_place_name']),
                    ':map_lat' => seller_apply_value_or_null($form['map_lat']),
                    ':map_lng' => seller_apply_value_or_null($form['map_lng']),
                    ':submitted_at' => $now,
                    ':updated_at' => $now,
                    ':id' => $existingApplicationId,
                ]);
                $applicationId = $existingApplicationId;
                try {
                    $pdo->prepare("DELETE FROM seller_documents WHERE application_id = :application_id")->execute([':application_id' => $applicationId]);
                } catch (Throwable $e) {
                    // keep going
                }
                seller_apply_insert_status_history($pdo, $applicationId, $userId, $existingStatus, $newStatus, 'Seller application resubmitted after rejection.', $now);
            } else {
                $stmt = $pdo->prepare("INSERT INTO seller_applications (user_id, application_status, farm_name, farm_logo_path, farm_address_line1, farm_address_line2, farm_road, farm_subdistrict, farm_district, farm_province, farm_postal_code, farm_phone, certificate_name, certificate_number, certificate_image_path, id_card_number, id_card_front_path, bank_name, bank_branch_name, bank_account_name, bank_account_number, bank_book_image_path, accepted_terms_version, accepted_terms_at, accepted_terms_ip, accepted_privacy_version, accepted_privacy_at, accepted_privacy_ip, map_place_name, map_lat, map_lng, submitted_at, created_at, updated_at) VALUES (:user_id, :application_status, :farm_name, :farm_logo_path, :farm_address_line1, :farm_address_line2, :farm_road, :farm_subdistrict, :farm_district, :farm_province, :farm_postal_code, :farm_phone, :certificate_name, :certificate_number, :certificate_image_path, :id_card_number, :id_card_front_path, :bank_name, :bank_branch_name, :bank_account_name, :bank_account_number, :bank_book_image_path, :accepted_terms_version, :accepted_terms_at, :accepted_terms_ip, :accepted_privacy_version, :accepted_privacy_at, :accepted_privacy_ip, :map_place_name, :map_lat, :map_lng, :submitted_at, :created_at, :updated_at)");
                $stmt->execute([
                    ':user_id' => $userId,
                    ':application_status' => $newStatus,
                    ':farm_name' => $form['farm_name'],
                    ':farm_logo_path' => $storedFarmLogo ? $storedFarmLogo['storage_path'] : null,
                    ':farm_address_line1' => $form['farm_address_line1'],
                    ':farm_address_line2' => seller_apply_value_or_null($form['farm_address_line2']),
                    ':farm_road' => seller_apply_value_or_null($form['farm_road']),
                    ':farm_subdistrict' => $form['farm_subdistrict'],
                    ':farm_district' => $form['farm_district'],
                    ':farm_province' => $form['farm_province'],
                    ':farm_postal_code' => $form['farm_postal_code'],
                    ':farm_phone' => $form['farm_phone'],
                    ':certificate_name' => seller_apply_value_or_null($form['certificate_name']),
                    ':certificate_number' => seller_apply_value_or_null($form['certificate_number']),
                    ':certificate_image_path' => $storedCertificate ? $storedCertificate['storage_path'] : null,
                    ':id_card_number' => seller_apply_digits_only($form['id_card_number']),
                    ':id_card_front_path' => $storedIdCardFront['storage_path'],
                    ':bank_name' => $form['bank_name'],
                    ':bank_branch_name' => $form['bank_branch_name'],
                    ':bank_account_name' => $form['bank_account_name'],
                    ':bank_account_number' => seller_apply_digits_only($form['bank_account_number']),
                    ':bank_book_image_path' => $storedBankBook ? $storedBankBook['storage_path'] : null,
                    ':accepted_terms_version' => $form['accepted_terms_version'],
                    ':accepted_terms_at' => $now,
                    ':accepted_terms_ip' => $ip !== '' ? $ip : null,
                    ':accepted_privacy_version' => $form['accepted_privacy_version'],
                    ':accepted_privacy_at' => $now,
                    ':accepted_privacy_ip' => $ip !== '' ? $ip : null,
                    ':map_place_name' => seller_apply_value_or_null($form['map_place_name']),
                    ':map_lat' => seller_apply_value_or_null($form['map_lat']),
                    ':map_lng' => seller_apply_value_or_null($form['map_lng']),
                    ':submitted_at' => $now,
                    ':created_at' => $now,
                    ':updated_at' => $now,
                ]);
                $applicationId = (int)$pdo->lastInsertId();
                seller_apply_insert_status_history($pdo, $applicationId, $userId, '', $newStatus, 'Seller application submitted by member with required consent confirmation and document uploads.', $now);
            }

            seller_apply_insert_document($pdo, $applicationId, 'farm_logo', $storedFarmLogo, $now);
            seller_apply_insert_document($pdo, $applicationId, 'certificate', $storedCertificate, $now);
            seller_apply_insert_document($pdo, $applicationId, 'id_card_front', $storedIdCardFront, $now);
            seller_apply_insert_document($pdo, $applicationId, 'bank_book', $storedBankBook, $now);

            seller_apply_insert_consent_log($pdo, $userId, $applicationId, 'seller_terms', $form['accepted_terms_version'], $termsDocumentHash !== '' ? $termsDocumentHash : null, 'modal_confirmed', $ip, $userAgent, $sessionId, $now);
            seller_apply_insert_consent_log($pdo, $userId, $applicationId, 'seller_terms', $form['accepted_terms_version'], $termsDocumentHash !== '' ? $termsDocumentHash : null, 'form_submitted', $ip, $userAgent, $sessionId, $now);
            seller_apply_insert_consent_log($pdo, $userId, $applicationId, 'privacy_policy', $form['accepted_privacy_version'], $privacyDocumentHash !== '' ? $privacyDocumentHash : null, 'modal_confirmed', $ip, $userAgent, $sessionId, $now);
            seller_apply_insert_consent_log($pdo, $userId, $applicationId, 'privacy_policy', $form['accepted_privacy_version'], $privacyDocumentHash !== '' ? $privacyDocumentHash : null, 'form_submitted', $ip, $userAgent, $sessionId, $now);

            $pdo->commit();

            seller_session_write_user([
                'id' => $userId,
                'first_name' => (string) ($user['first_name'] ?? ''),
                'last_name' => (string) ($user['last_name'] ?? ''),
                'email' => $memberEmail,
                'role' => 'seller',
                'seller_application_status' => $newStatus,
            ]);

            $submittedAtFormatted = seller_apply_format_datetime($submittedAt);
            $sellerEmailResult = bv_mailer_send([$memberEmail], 'Seller application received - ' . $siteName, seller_apply_seller_email_body($fullNameDefault, $memberEmail, $submittedAtFormatted, $newStatus, $form['accepted_terms_version'], $form['accepted_privacy_version'], seller_apply_build_absolute_url($sellerTermsUrl), seller_apply_build_absolute_url($sellerTermsUrlTh), seller_apply_build_absolute_url($privacyPolicyUrl), seller_apply_build_absolute_url($privacyPolicyUrlTh), $siteName), ['from_email' => $mailFromEmail, 'from_name' => $mailFromName, 'reply_to' => $mailFromEmail]);
            if (empty($sellerEmailResult['ok'])) {
                error_log('seller apply mail failed: seller confirmation not sent for application #' . $applicationId . ' :: ' . ($sellerEmailResult['message'] ?? 'unknown'));
            }

            $adminBody = seller_apply_admin_email_body($fullNameDefault, $memberEmail, $applicationId, $submittedAtFormatted, $form, $siteName);
            foreach ($adminNotificationEmails as $adminEmail) {
                $adminEmail = trim((string)$adminEmail);
                if ($adminEmail === '' || !filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) {
                    continue;
                }
                $adminEmailResult = bv_mailer_send([$adminEmail], 'New seller application submitted - #' . $applicationId . ' - ' . $siteName, $adminBody, ['from_email' => $mailFromEmail, 'from_name' => $mailFromName, 'reply_to' => $memberEmail]);
                if (empty($adminEmailResult['ok'])) {
                    error_log('seller apply mail failed: admin notification not sent to ' . $adminEmail . ' for application #' . $applicationId . ' :: ' . ($adminEmailResult['message'] ?? 'unknown'));
                }
            }

            $_SESSION['seller_apply_success'] = $existingStatus === 'rejected'
                ? 'Your seller application has been resubmitted successfully.'
                : 'Your seller application has been submitted successfully.';
            header('Location: /seller/apply.php');
            exit;
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            seller_apply_cleanup_files($movedFiles);
            $errors[] = 'Unable to submit your seller application right now.';
            error_log('seller apply failed: ' . $e->getMessage());
        }
    }
}

$csrf = seller_apply_csrf_token();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Seller Application | Bettavaro</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex,nofollow,noarchive">
    <style>
        :root{--bg:#08110d;--panel:#121a16;--line:rgba(255,255,255,.08);--line-2:rgba(207,176,107,.18);--text:#f4f1e8;--muted:#aab7ad;--gold:#cfb06b;--gold-2:#e7d4a2;--green:#14311f;--green-line:#2f6a48;--green-text:#d7ffe4;--red:#3a1717;--red-line:#7a2a2a;--red-text:#ffd3d3;--shadow:0 18px 50px rgba(0,0,0,.28)}
        *{box-sizing:border-box} body{margin:0;font-family:Arial,Helvetica,sans-serif;color:var(--text);background:radial-gradient(circle at top, #122117 0%, #08110d 45%, #050906 100%)}
        .wrap{max-width:1240px;margin:0 auto;padding:28px 18px 56px}.topbar{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:22px}.brand small{color:var(--gold);text-transform:uppercase;letter-spacing:.12em;font-weight:700;display:block;margin-bottom:6px}.brand h1{margin:0;font-size:30px;line-height:1.1}.actions{display:flex;gap:10px;flex-wrap:wrap}
        .btn{display:inline-flex;align-items:center;justify-content:center;min-height:46px;padding:0 18px;border-radius:12px;text-decoration:none;font-weight:700;border:1px solid transparent;cursor:pointer}.btn-primary{background:var(--gold);color:#111}.btn-secondary{background:transparent;color:var(--text);border-color:var(--line)}.btn-ghost{background:rgba(255,255,255,.02);color:var(--text);border-color:var(--line)}
        .card{background:linear-gradient(180deg, rgba(255,255,255,.03), rgba(255,255,255,.015));border:1px solid var(--line);border-radius:22px;box-shadow:var(--shadow);overflow:hidden}.card-body{padding:24px}.grid{display:grid;grid-template-columns:.92fr 1.08fr;gap:18px}
        .flash{margin-bottom:18px;padding:14px 16px;border-radius:14px}.flash-success{background:var(--green);border:1px solid var(--green-line);color:var(--green-text)}.flash-error{background:var(--red);border:1px solid var(--red-line);color:var(--red-text)}
        .hero-title{margin:0 0 8px;font-size:34px;line-height:1.08}.hero-text{margin:0;color:var(--muted);line-height:1.8}.badge{display:inline-flex;align-items:center;padding:8px 12px;border-radius:999px;background:rgba(207,176,107,.14);color:var(--gold-2);border:1px solid rgba(207,176,107,.28);font-size:13px;font-weight:800;letter-spacing:.02em;margin-bottom:12px}
        .section-title{margin:0 0 14px;font-size:20px}.field{margin-bottom:16px}.field label{display:block;margin-bottom:8px;font-size:14px;font-weight:700}.field input,.field textarea{width:100%;padding:13px 14px;border-radius:14px;border:1px solid #314038;background:#0d1411;color:#fff;font-size:15px}.field input[readonly]{opacity:.85}
        .field-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.note{color:var(--muted);font-size:13px;line-height:1.7;margin-top:7px}.list{display:grid;gap:12px}.list-item{padding:14px 15px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.02)}.list-item strong{display:block;margin-bottom:6px;font-size:15px}.list-item span{color:var(--muted);font-size:14px;line-height:1.7}
.list-item-clickable{display:block;position:relative;color:inherit;text-decoration:none;transition:transform .16s ease,border-color .16s ease,background .16s ease,box-shadow .16s ease}
.list-item-clickable:hover{transform:translateY(-1px);background:rgba(255,255,255,.04);border-color:rgba(207,176,107,.28);box-shadow:0 12px 30px rgba(0,0,0,.18)}
.list-item-clickable strong,.list-item-clickable span{color:inherit}
        .block-title{margin:22px 0 12px;font-size:16px;font-weight:800;color:var(--gold-2);text-transform:uppercase;letter-spacing:.05em}.legal-box{margin-bottom:16px;padding:16px;border:1px solid var(--line-2);border-radius:18px;background:rgba(207,176,107,.06)}.legal-box h4{margin:0 0 8px;font-size:16px}.legal-box p{margin:0 0 12px;color:var(--muted);line-height:1.8}.legal-links{display:flex;gap:10px;flex-wrap:wrap}
        .checkbox-row{display:flex;align-items:flex-start;gap:10px;margin-bottom:14px;padding:14px;border:1px solid var(--line);border-radius:14px;background:rgba(255,255,255,.02)}.checkbox-row input{margin-top:3px}.checkbox-row strong{display:block;margin-bottom:4px}.checkbox-row .sub{display:block;color:var(--muted);font-size:13px;line-height:1.6}.version-pill{display:inline-flex;align-items:center;min-height:34px;padding:0 12px;border-radius:999px;background:rgba(255,255,255,.04);border:1px solid var(--line);color:var(--gold-2);font-weight:700;font-size:13px}
        .file-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.file-box{padding:14px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.02)}.file-box h4{margin:0 0 8px;font-size:15px}.file-box p{margin:0 0 10px;color:var(--muted);font-size:13px;line-height:1.7}.file-box input[type="file"]{padding:12px;background:#0d1411;border:1px solid #314038;border-radius:14px;color:#fff}
        ul.error-list{margin:0;padding-left:18px}.submit-row{display:flex;justify-content:flex-end;margin-top:18px}.small-muted{font-size:12px;color:var(--muted)}.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.68);display:none;align-items:center;justify-content:center;z-index:9999;padding:18px}.modal-backdrop.active{display:flex}.modal{width:100%;max-width:640px;background:#0c130f;border:1px solid var(--line-2);border-radius:24px;box-shadow:0 30px 80px rgba(0,0,0,.45);overflow:hidden}.modal-head{padding:20px 22px 12px;border-bottom:1px solid var(--line)}.modal-head h3{margin:0;font-size:24px}.modal-body{padding:20px 22px}.modal-body p{margin:0 0 12px;line-height:1.8;color:var(--muted)}.modal-important{padding:14px;border:1px solid rgba(207,176,107,.28);background:rgba(207,176,107,.08);border-radius:16px;color:var(--gold-2);font-weight:700;line-height:1.7;margin-bottom:14px}.modal-actions{display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end;padding:0 22px 22px}.alert-inline{margin-top:10px;color:#ffd3d3;font-size:13px}.offer-stat-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin-top:14px}.offer-stat{padding:14px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.03)}.offer-stat strong{display:block;font-size:24px;color:var(--gold-2);margin-bottom:4px}.offer-stat span{display:block;color:var(--muted);font-size:13px}
		.offer-thread-badges{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.offer-thread-badge{display:inline-flex;align-items:center;padding:6px 10px;border-radius:999px;font-size:12px;font-weight:800;letter-spacing:.02em;border:1px solid transparent}
.offer-thread-badge-needs-reply{background:#7f1d1d;color:#fecaca;border-color:#b91c1c}
.offer-thread-badge-open{background:#1e3a8a;color:#dbeafe;border-color:#3b82f6}
.offer-thread-badge-ready{background:#14532d;color:#dcfce7;border-color:#22c55e}
.offer-thread-badge-completed{background:#3f3f46;color:#e4e4e7;border-color:#71717a}
.offer-thread-actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:12px}
.offer-reply-now{display:inline-flex;align-items:center;justify-content:center;min-height:36px;padding:0 12px;border-radius:999px;background:var(--gold);color:#111;text-decoration:none;font-size:12px;font-weight:900;border:1px solid rgba(207,176,107,.28);position:relative;z-index:2}
.offer-reply-now:hover{background:var(--gold-2)}
.summary-stat-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin-top:12px}.summary-stat{padding:14px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.03)}.summary-stat strong{display:block;font-size:23px;color:var(--gold-2);margin-bottom:4px}.summary-stat span{display:block;color:var(--muted);font-size:13px}.mini-table{width:100%;border-collapse:collapse;margin-top:14px}.mini-table th,.mini-table td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}.mini-table th{color:var(--gold-2);font-size:12px;text-transform:uppercase;letter-spacing:.04em}.request-type-pill{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;background:rgba(207,176,107,.14);border:1px solid rgba(207,176,107,.28);font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.04em}.summary-empty{padding:14px;border:1px dashed var(--line);border-radius:12px;color:var(--muted);margin-top:14px}.summary-link-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}
        .table-scroll{overflow-x:auto;max-width:100%;-webkit-overflow-scrolling:touch;border:1px solid var(--line);border-radius:12px;margin-top:14px}
        .table-scroll .mini-table{margin-top:0;min-width:980px}
        .order-link{color:var(--gold-2);font-weight:700;text-decoration:none;border-bottom:1px dashed rgba(207,176,107,.45)}
        .order-link:hover{color:#fff;border-bottom-color:rgba(255,255,255,.55)}
        @media (max-width:940px){.grid,.field-grid,.file-grid,.offer-stat-grid{grid-template-columns:1fr}.submit-row{justify-content:stretch}.submit-row .btn{width:100%}}
    </style>
</head>
<body>
<div class="wrap">
    <div class="topbar">
        <div class="brand"><small>Seller Area</small><h1>Seller Application</h1></div>
        <div class="actions">
            <a class="btn btn-secondary" href="/member/index.php">Back to Dashboard</a>
            <?php if (seller_is_approved_safe()): ?>
                <a class="btn btn-ghost" href="/seller/offers.php">Seller Offers</a>
            <?php endif; ?>
            <a class="btn btn-primary" href="/logout.php">Logout</a>
        </div>
    </div>

    <?php if ($flashSuccess !== ''): ?><div class="flash flash-success"><?php echo e($flashSuccess); ?></div><?php endif; ?>
    <?php if ($infoMessage !== ''): ?><div class="flash flash-success"><?php echo e($infoMessage); ?><?php if ($existingStatus !== ''): ?> Current status: <strong><?php echo e($existingStatus); ?></strong><?php endif; ?></div><?php endif; ?>
    <?php if (!empty($errors)): ?><div class="flash flash-error"><ul class="error-list"><?php foreach ($errors as $error): ?><li><?php echo e($error); ?></li><?php endforeach; ?></ul></div><?php endif; ?>

    <div class="grid">
        <div class="card">
            <div class="card-body">
                <div class="badge">Bettavaro Marketplace</div>
                <h2 class="hero-title"><?php echo $canSubmit ? 'Join as a verified seller' : 'Seller application status'; ?></h2>
                <p class="hero-text">
                    This page is now aligned with the current system: approved sellers stay on the member dashboard, while this application page handles apply, review, and rejected resubmission flow cleanly.
                </p>

                <div class="list" style="margin-top:18px;">
                    <div class="list-item"><strong>Identity and trust</strong><span>Seller identity, address, and required documents are collected for review and fraud prevention.</span></div>
                    <div class="list-item"><strong>Future seller listings ready</strong><span>Approved sellers can stay on the member dashboard now, and later plug straight into Seller Listings without changing login structure.</span></div>
                    <div class="list-item"><strong>Consent logging and bilingual legal links</strong><span>Seller Terms and Privacy Policy acceptance are logged with version, IP, session, and user agent.</span></div>
                    <div class="list-item"><strong>Offer system ready after approval</strong><span>Once approved, your listing negotiations will run through the offer system and can be managed from the seller dashboard without changing this onboarding flow.</span></div>
                </div>

                <?php if ($offerFeatureAvailable && seller_is_approved_safe()): ?>
                    <div class="block-title">Seller offer summary</div>
<div class="offer-stat-grid">
    <div class="offer-stat"><strong><?php echo (int)$offerStats['total']; ?></strong><span>Total offers</span></div>
    <div class="offer-stat"><strong><?php echo (int)$offerStats['open']; ?></strong><span>Open offers</span></div>
    <div class="offer-stat"><strong><?php echo (int)$offerStats['needs_reply']; ?></strong><span>Needs reply</span></div>
    <div class="offer-stat"><strong><?php echo (int)$offerStats['accepted_or_ready']; ?></strong><span>Accepted / checkout ready</span></div>
    <div class="offer-stat"><strong><?php echo (int)$offerStats['completed']; ?></strong><span>Completed deals</span></div>
</div>

                    <div class="legal-links" style="margin-top:14px;">
                        <a class="btn btn-ghost" href="/seller/offers.php">Open Seller Offers</a>
                        <a class="btn btn-ghost" href="/member/offers.php">Buyer Offer Threads</a>
                    </div>

                    <?php if ($recentOffers): ?>
                        <div class="block-title">Needs Reply Now</div>
                        <div class="list">
                            <?php foreach ($recentOffers as $offer): ?>
                                <?php
                                $offerIdRow = (int)($offer['id'] ?? 0);
                                $offerStatusRow = strtolower(trim((string)($offer['status'] ?? 'unknown')));
                                $needsReplyRow = !empty($offer['needs_reply']);
                                $offerThreadUrl = '/offer.php?id=' . $offerIdRow;

                                $statusBadgeClass = 'offer-thread-badge-open';
                                $statusBadgeLabel = ucfirst($offerStatusRow !== '' ? $offerStatusRow : 'unknown');

                                if (in_array($offerStatusRow, ['seller_accepted', 'buyer_checkout_ready'], true)) {
                                    $statusBadgeClass = 'offer-thread-badge-ready';
                                    $statusBadgeLabel = 'Checkout Ready';
                                } elseif ($offerStatusRow === 'completed') {
                                    $statusBadgeClass = 'offer-thread-badge-completed';
                                    $statusBadgeLabel = 'Completed';
                                } elseif ($offerStatusRow === 'open') {
                                    $statusBadgeClass = 'offer-thread-badge-open';
                                    $statusBadgeLabel = 'Open';
                                }
                                ?>
                                <a class="list-item list-item-clickable" href="<?php echo e($offerThreadUrl); ?>">
                                    <strong>
                                        <?php echo e((string)($offer['listing_title'] ?? ('Listing #' . (int)($offer['listing_id'] ?? 0)))); ?>
                                    </strong>
                                    <span>
                                        Offer #<?php echo $offerIdRow; ?>
                                        • Status: <?php echo e((string)($offer['status'] ?? 'unknown')); ?>
                                        <?php if (!empty($offer['latest_offer_price']) && is_numeric($offer['latest_offer_price'])): ?>
                                            • Latest: <?php echo e(number_format((float)$offer['latest_offer_price'], 2) . ' ' . strtoupper((string)($offer['currency'] ?? 'USD'))); ?>
                                        <?php endif; ?>
                                    </span>

                                    <div class="offer-thread-actions">
                                        <div class="offer-thread-badges">
                                            <?php if ($needsReplyRow): ?>
                                                <span class="offer-thread-badge offer-thread-badge-needs-reply">Needs Reply</span>
                                            <?php endif; ?>
                                            <span class="offer-thread-badge <?php echo e($statusBadgeClass); ?>">
                                                <?php echo e($statusBadgeLabel); ?>
                                            </span>
                                        </div>

                                        <?php if ($needsReplyRow): ?>
                                            <span class="offer-reply-now">Reply now</span>
                                        <?php endif; ?>
                                    </div>
                                </a>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>

                <?php if (seller_is_approved_safe() && function_exists('seller_cancel_refund_get_summary')): ?>
                    <div class="block-title">Seller Cancel / Refund Summary</div>
                    <div class="summary-stat-grid">
                        <div class="summary-stat"><strong><?php echo (int)($cancelRefundSummary['pending_cancel_count'] ?? 0); ?></strong><span>Pending Cancel Requests</span></div>
                        <div class="summary-stat"><strong><?php echo (int)($cancelRefundSummary['pending_refund_count'] ?? 0); ?></strong><span>Pending Refund Requests</span></div>
                        <div class="summary-stat"><strong><?php echo (int)($cancelRefundSummary['refund_ready_count'] ?? 0); ?></strong><span>Approved Refunds Awaiting Processing</span></div>
                        <div class="summary-stat"><strong><?php echo (int)($cancelRefundSummary['completed_refund_count'] ?? 0); ?></strong><span>Refunded / Completed</span></div>
                        <div class="summary-stat"><strong><?php echo (int)($cancelRefundSummary['total_open_requests'] ?? 0); ?></strong><span>Total Open Requests</span></div>
                    </div>

                    <?php if ($cancelRefundRecent): ?>
                        <div class="table-scroll">
                        <table class="mini-table" aria-label="Recent cancel and refund requests">
                            <thead>
                                <tr>
                                    <th>Order</th>
                                    <th>Listing</th>
                                    <th>Buyer</th>
                                    <th>Type</th>
                                    <th>Status</th>
                                    <th>Payment</th>
                                    <th>Amount</th>
                                    <th>Requested</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($cancelRefundRecent as $requestRow): ?>
                                <?php
                                $requestType = (string)($requestRow['request_type'] ?? '');
                                $requestStatus = (string)($requestRow['status'] ?? '');
                                $badge = function_exists('seller_cancel_refund_status_badge')
                                    ? seller_cancel_refund_status_badge($requestType, $requestStatus)
                                    : ['label' => ucfirst($requestStatus), 'class' => 'offer-thread-badge-open'];
                                $requestOrderId = isset($requestRow['order_id']) && is_numeric($requestRow['order_id']) ? (int)$requestRow['order_id'] : 0;
                                $requestUrl = $requestOrderId > 0 ? '/seller/order_detail.php?id=' . $requestOrderId : '';
                                ?>
                                <tr>
                                    <td>
                                        <?php $orderLabel = (string)($requestRow['order_code'] ?? ('Order #' . (int)($requestRow['order_id'] ?? 0))); ?>
                                        <?php if ($requestUrl !== ''): ?>
                                            <a class="order-link" href="<?php echo e($requestUrl); ?>"><?php echo e($orderLabel); ?></a>
                                        <?php else: ?>
                                            <?php echo e($orderLabel); ?>
                                        <?php endif; ?>
                                    </td>
                                    <td><?php echo e((string)($requestRow['listing_title'] ?? ('Listing #' . (int)($requestRow['listing_id'] ?? 0)))); ?></td>
                                    <td><?php echo e((string)($requestRow['buyer_name'] ?? '—')); ?></td>
                                    <td><span class="request-type-pill"><?php echo e($requestType !== '' ? $requestType : 'request'); ?></span></td>
                                    <td><span class="offer-thread-badge <?php echo e((string)($badge['class'] ?? 'offer-thread-badge-open')); ?>"><?php echo e((string)($badge['label'] ?? 'Unknown')); ?></span></td>
                                    <td><?php echo e((string)($requestRow['payment_status'] ?? '—')); ?></td>
                                    <td><?php echo e(function_exists('seller_cancel_refund_money') ? seller_cancel_refund_money($requestRow['amount'] ?? null, (string)($requestRow['currency'] ?? 'USD')) : '—'); ?></td>
                                    <td><?php echo e(seller_apply_format_datetime((string)($requestRow['requested_at'] ?? ''))); ?></td>
                                    <td>
                                        <?php if ($requestUrl !== ''): ?>
                                            <a class="btn btn-ghost" style="min-height:34px;padding:0 10px;font-size:12px;" href="<?php echo e($requestUrl); ?>">View Order</a>
                                        <?php else: ?>
                                            <span class="note">—</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                        </div>
                    <?php else: ?>
                        <div class="summary-empty">No cancel or refund requests right now.</div>
                    <?php endif; ?>

                    <?php if ($cancelRefundOrderListUrl !== ''): ?>
                        <div class="summary-link-row">
                            <a class="btn btn-ghost" href="<?php echo e($cancelRefundOrderListUrl); ?>?seller_request=open">View all related orders</a>
                            <a class="btn btn-ghost" href="<?php echo e($cancelRefundOrderListUrl); ?>?seller_request=cancel">Cancel requests</a>
                            <a class="btn btn-ghost" href="<?php echo e($cancelRefundOrderListUrl); ?>?seller_request=refund">Refund requests</a>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>

                <div class="block-title">Legal review before submit</div>
                <div class="legal-box">
                    <h4>Read before applying</h4>
                    <p>You must read the seller agreement and privacy policy in full before becoming a seller on Bettavaro.</p>
                    <div class="legal-links">
                        <a class="btn btn-ghost" href="<?php echo e($sellerTermsUrl); ?>" target="_blank" rel="noopener noreferrer">Seller Terms EN</a>
                        <a class="btn btn-ghost" href="<?php echo e($sellerTermsUrlTh); ?>" target="_blank" rel="noopener noreferrer">Seller Terms TH</a>
                        <a class="btn btn-ghost" href="<?php echo e($privacyPolicyUrl); ?>" target="_blank" rel="noopener noreferrer">Privacy EN</a>
                        <a class="btn btn-ghost" href="<?php echo e($privacyPolicyUrlTh); ?>" target="_blank" rel="noopener noreferrer">Privacy TH</a>
                    </div>
                </div>

                <p class="note">Good onboarding prevents future chaos. The boring parts are the parts that save your neck later.</p>
            </div>
        </div>

        <div class="card">
            <div class="card-body">
                <h3 class="section-title"><?php echo $canSubmit ? 'Application form' : 'Application overview'; ?></h3>

                <?php if (!$canSubmit): ?>
                    <div class="list">
                        <div class="list-item"><strong>Current status</strong><span><?php echo e($existingStatus !== '' ? $existingStatus : 'not_applied'); ?></span></div>
                        <div class="list-item"><strong>Next step</strong><span>
                            <?php
                            if (seller_is_approved_safe()) {
                                echo 'Use the member dashboard as your seller home until Seller Listings is added.';
                            } elseif ($existingStatus === 'submitted' || $existingStatus === 'under_review' || $existingStatus === 'draft') {
                                echo 'Wait for admin review. This page keeps your seller paperwork in one place.';
                            } elseif ($existingStatus === 'suspended') {
                                echo 'Contact support or admin for review before any seller tools are reopened.';
                            } elseif ($role === 'admin') {
                                echo 'Admin accounts should use admin tools, not seller onboarding.';
                            } else {
                                echo 'This account cannot submit a new application right now.';
                            }
                            ?>
                        </span></div>

                        <?php if (seller_is_approved_safe()): ?>
                            <div class="list-item"><strong>Offer system</strong><span>Your seller account can already use the offer flow. Open the seller offer dashboard to manage buyer negotiations.</span></div>
                            <div class="legal-links">
                                <a class="btn btn-ghost" href="/seller/offers.php">Open Seller Offers</a>
                                <a class="btn btn-ghost" href="/member/offers.php">Open Buyer Offers</a>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                <form method="post" action="/seller/apply.php" enctype="multipart/form-data" novalidate id="sellerApplyForm">
                    <input type="hidden" name="csrf_token" value="<?php echo e($csrf); ?>">
                    <input type="hidden" name="accepted_terms_version" value="<?php echo e($form['accepted_terms_version']); ?>">
                    <input type="hidden" name="accepted_privacy_version" value="<?php echo e($form['accepted_privacy_version']); ?>">
                    <input type="hidden" name="terms_modal_confirmed" id="terms_modal_confirmed" value="<?php echo e($form['terms_modal_confirmed']); ?>">
                    <input type="hidden" name="privacy_modal_confirmed" id="privacy_modal_confirmed" value="<?php echo e($form['privacy_modal_confirmed']); ?>">
                    <div class="field"><label>Member Name</label><input type="text" value="<?php echo e($fullNameDefault); ?>" readonly></div>
                    <div class="field"><label>Email</label><input type="email" value="<?php echo e((string)($user['email'] ?? '')); ?>" readonly></div>
                    <div class="block-title">Farm details</div>
                    <div class="field"><label for="farm_name">Farm Name *</label><input type="text" id="farm_name" name="farm_name" value="<?php echo e($form['farm_name']); ?>" required></div>
                    <div class="field-grid"><div class="field"><label for="farm_phone">Farm Phone *</label><input type="text" id="farm_phone" name="farm_phone" value="<?php echo e($form['farm_phone']); ?>" required></div><div class="field"><label for="farm_postal_code">Postal Code *</label><input type="text" id="farm_postal_code" name="farm_postal_code" value="<?php echo e($form['farm_postal_code']); ?>" required></div></div>
                    <div class="field"><label for="farm_address_line1">Address Line 1 *</label><input type="text" id="farm_address_line1" name="farm_address_line1" value="<?php echo e($form['farm_address_line1']); ?>" placeholder="House number / village / building" required></div>
                    <div class="field"><label for="farm_address_line2">Address Line 2</label><input type="text" id="farm_address_line2" name="farm_address_line2" value="<?php echo e($form['farm_address_line2']); ?>" placeholder="Soi / extra details"></div>
                    <div class="field"><label for="farm_road">Road</label><input type="text" id="farm_road" name="farm_road" value="<?php echo e($form['farm_road']); ?>"></div>
                    <div class="field-grid"><div class="field"><label for="farm_subdistrict">Subdistrict *</label><input type="text" id="farm_subdistrict" name="farm_subdistrict" value="<?php echo e($form['farm_subdistrict']); ?>" required></div><div class="field"><label for="farm_district">District *</label><input type="text" id="farm_district" name="farm_district" value="<?php echo e($form['farm_district']); ?>" required></div></div>
                    <div class="field"><label for="farm_province">Province *</label><input type="text" id="farm_province" name="farm_province" value="<?php echo e($form['farm_province']); ?>" required></div>
                    <div class="field"><label for="map_place_name">Map Place Name</label><input type="text" id="map_place_name" name="map_place_name" value="<?php echo e($form['map_place_name']); ?>" placeholder="Farm location name on map"></div>
                    <div class="field-grid"><div class="field"><label for="map_lat">Map Latitude</label><input type="text" id="map_lat" name="map_lat" value="<?php echo e($form['map_lat']); ?>"></div><div class="field"><label for="map_lng">Map Longitude</label><input type="text" id="map_lng" name="map_lng" value="<?php echo e($form['map_lng']); ?>"></div></div>
                    <div class="block-title">Verification details</div>
                    <div class="field-grid"><div class="field"><label for="certificate_name">Certificate Name</label><input type="text" id="certificate_name" name="certificate_name" value="<?php echo e($form['certificate_name']); ?>"></div><div class="field"><label for="certificate_number">Certificate Number</label><input type="text" id="certificate_number" name="certificate_number" value="<?php echo e($form['certificate_number']); ?>"></div></div>
                    <div class="field"><label for="id_card_number">ID Card Number *</label><input type="text" id="id_card_number" name="id_card_number" value="<?php echo e($form['id_card_number']); ?>" required></div>
                    <div class="field-grid"><div class="field"><label for="bank_name">Bank Name *</label><input type="text" id="bank_name" name="bank_name" value="<?php echo e($form['bank_name']); ?>" required></div><div class="field"><label for="bank_branch_name">Bank Branch Name *</label><input type="text" id="bank_branch_name" name="bank_branch_name" value="<?php echo e($form['bank_branch_name']); ?>" required></div></div>
                    <div class="field-grid"><div class="field"><label for="bank_account_name">Bank Account Name *</label><input type="text" id="bank_account_name" name="bank_account_name" value="<?php echo e($form['bank_account_name']); ?>" required></div><div class="field"><label for="bank_account_number">Bank Account Number *</label><input type="text" id="bank_account_number" name="bank_account_number" value="<?php echo e($form['bank_account_number']); ?>" required></div></div>
                    <div class="block-title">Required uploads</div>
                    <div class="file-grid">
                        <div class="file-box"><h4>Farm Logo</h4><p>Optional. Accepted: JPG, PNG, WEBP. Max 8 MB.</p><input type="file" name="farm_logo_file" accept=".jpg,.jpeg,.png,.webp"></div>
                        <div class="file-box"><h4>Government Farmer Certificate</h4><p>Optional. Accepted: JPG, PNG, WEBP, PDF. Max 8 MB.</p><input type="file" name="certificate_image_file" accept=".jpg,.jpeg,.png,.webp,.pdf"></div>
                        <div class="file-box"><h4>ID Card Picture *</h4><p>Required. Accepted: JPG, PNG, WEBP. Max 8 MB.</p><input type="file" name="id_card_front_file" accept=".jpg,.jpeg,.png,.webp" required></div>
                        <div class="file-box"><h4>Bank Book Image</h4><p>Optional but recommended. Accepted: JPG, PNG, WEBP, PDF. Max 8 MB.</p><input type="file" name="bank_book_image_file" accept=".jpg,.jpeg,.png,.webp,.pdf"></div>
                    </div>
                    <div class="block-title">Offer system after approval</div>
                    <div class="legal-box">
                        <h4>What unlocks after approval</h4>
                        <p>When this application is approved, your seller account can receive buyer offers directly on listings and manage all negotiations from the seller offer dashboard.</p>
                        <div class="legal-links">
                            <a class="btn btn-ghost" href="/member/index.php">View Dashboard</a>
                            <a class="btn btn-ghost" href="/member/offers.php">Buyer Offer Threads</a>
                        </div>
                    </div>
                    <div class="block-title">Legal confirmations</div>
                    <div class="field" style="margin-bottom:10px;"><span class="version-pill">Seller Terms Version: <?php echo e($form['accepted_terms_version']); ?></span></div>
                    <div class="field" style="margin-bottom:16px;"><span class="version-pill">Privacy Policy Version: <?php echo e($form['accepted_privacy_version']); ?></span></div>
                    <label class="checkbox-row"><input type="checkbox" name="accept_terms" id="accept_terms" value="1" <?php echo $form['accept_terms'] === '1' ? 'checked' : ''; ?>><span><strong>I confirm that I have read and accepted the seller terms and conditions.</strong><span class="sub">When you tick this box, a confirmation popup will appear.</span></span></label>
                    <label class="checkbox-row"><input type="checkbox" name="accept_privacy" id="accept_privacy" value="1" <?php echo $form['accept_privacy'] === '1' ? 'checked' : ''; ?>><span><strong>I confirm that I have read and accepted the privacy policy.</strong><span class="sub">When you tick this box, a confirmation popup will appear.</span></span></label>
                    <div class="small-muted">By submitting this form, you confirm that the uploaded documents and all information provided are true and belong to you.</div>
                    <div class="submit-row"><button class="btn btn-primary" type="submit"><?php echo $existingStatus === 'rejected' ? 'Resubmit Seller Application' : 'Submit Seller Application'; ?></button></div>
                </form>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<div class="modal-backdrop" id="consentModalBackdrop" aria-hidden="true">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="consentModalTitle">
        <div class="modal-head"><h3 id="consentModalTitle">Confirmation Required</h3></div>
        <div class="modal-body">
            <div class="modal-important" id="consentModalImportant">By clicking confirm, you acknowledge that you have carefully read the document and accept its legal effect.</div>
            <p id="consentModalText">Please read the linked document carefully before continuing.</p>
            <div class="legal-links"><a class="btn btn-ghost" href="#" target="_blank" rel="noopener noreferrer" id="consentModalOpenLink">Open document</a></div>
            <div class="alert-inline" id="consentModalAlert">การคลิกยืนยันถือว่าท่านได้อ่านและยอมรับเงื่อนไขโดยละเอียดแล้ว</div>
        </div>
        <div class="modal-actions"><button type="button" class="btn btn-secondary" id="consentModalCancel">Cancel</button><button type="button" class="btn btn-primary" id="consentModalConfirm">I have read and accept</button></div>
    </div>
</div>
<script>
(function(){var form=document.getElementById('sellerApplyForm');if(!form)return;var modalBackdrop=document.getElementById('consentModalBackdrop');var modalTitle=document.getElementById('consentModalTitle');var modalText=document.getElementById('consentModalText');var modalOpenLink=document.getElementById('consentModalOpenLink');var modalCancel=document.getElementById('consentModalCancel');var modalConfirm=document.getElementById('consentModalConfirm');var termsCheckbox=document.getElementById('accept_terms');var privacyCheckbox=document.getElementById('accept_privacy');var termsConfirmedInput=document.getElementById('terms_modal_confirmed');var privacyConfirmedInput=document.getElementById('privacy_modal_confirmed');var currentConsentKey='';var consentConfig={terms:{checkbox:termsCheckbox,confirmedInput:termsConfirmedInput,title:'Confirm Seller Terms and Conditions',text:'You are confirming that you have read the Seller Terms and Conditions carefully and accept the obligations, restrictions, and legal effect of becoming a seller on this website.',link:<?php echo json_encode($sellerTermsUrl); ?>},privacy:{checkbox:privacyCheckbox,confirmedInput:privacyConfirmedInput,title:'Confirm Privacy Policy',text:'You are confirming that you have read the Privacy Policy carefully and understand how your personal data and uploaded documents will be collected, stored, reviewed, and used.',link:<?php echo json_encode($privacyPolicyUrl); ?>}};function openConsentModal(key){if(!consentConfig[key])return;currentConsentKey=key;modalTitle.textContent=consentConfig[key].title;modalText.textContent=consentConfig[key].text;modalOpenLink.setAttribute('href',consentConfig[key].link);modalBackdrop.classList.add('active');modalBackdrop.setAttribute('aria-hidden','false')}function closeConsentModal(){modalBackdrop.classList.remove('active');modalBackdrop.setAttribute('aria-hidden','true');currentConsentKey=''}function rollbackConsent(key){if(!consentConfig[key])return;consentConfig[key].checkbox.checked=false;consentConfig[key].confirmedInput.value=''}function confirmConsent(key){if(!consentConfig[key])return;consentConfig[key].checkbox.checked=true;consentConfig[key].confirmedInput.value='1'}function bindCheckbox(key){var cfg=consentConfig[key];if(!cfg||!cfg.checkbox)return;cfg.checkbox.addEventListener('change',function(){if(cfg.checkbox.checked&&cfg.confirmedInput.value!=='1'){openConsentModal(key)}else if(!cfg.checkbox.checked){cfg.confirmedInput.value=''}})}bindCheckbox('terms');bindCheckbox('privacy');modalCancel.addEventListener('click',function(){if(currentConsentKey!=='')rollbackConsent(currentConsentKey);closeConsentModal()});modalConfirm.addEventListener('click',function(){if(currentConsentKey!=='')confirmConsent(currentConsentKey);closeConsentModal()});modalBackdrop.addEventListener('click',function(event){if(event.target===modalBackdrop){if(currentConsentKey!=='')rollbackConsent(currentConsentKey);closeConsentModal()}});document.addEventListener('keydown',function(event){if(event.key==='Escape'&&modalBackdrop.classList.contains('active')){if(currentConsentKey!=='')rollbackConsent(currentConsentKey);closeConsentModal()}});form.addEventListener('submit',function(event){if(termsCheckbox&&termsCheckbox.checked&&termsConfirmedInput.value!=='1'){event.preventDefault();openConsentModal('terms');return}if(privacyCheckbox&&privacyCheckbox.checked&&privacyConfirmedInput.value!=='1'){event.preventDefault();openConsentModal('privacy');return}if(termsCheckbox&&!termsCheckbox.checked){event.preventDefault();alert('Please accept the Seller Terms and Conditions before submitting.');return}if(privacyCheckbox&&!privacyCheckbox.checked){event.preventDefault();alert('Please accept the Privacy Policy before submitting.')}})})();
</script>
</body>
</html>
