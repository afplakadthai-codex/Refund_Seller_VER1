<?php
declare(strict_types=1);

if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}

require_once dirname(__DIR__) . '/includes/order_refund.php';
require_once dirname(__DIR__) . '/includes/stripe_refund_engine.php';

$guardFiles = [
    __DIR__ . '/_guard.php',
    __DIR__ . '/admin_auth.php',
    __DIR__ . '/auth.php',
    dirname(__DIR__) . '/includes/admin_auth.php',
    dirname(__DIR__) . '/includes/auth_admin.php',
];

foreach ($guardFiles as $gf) {
    if (is_file($gf)) {
        require_once $gf;
    }
}

if (!function_exists('bv_admin_refund_action_set_flash')) {
    function bv_admin_refund_action_set_flash(string $type, string $message): void
    {
        $type = strtolower(trim($type));
        if (!in_array($type, ['success', 'error', 'warning', 'info'], true)) {
            $type = 'info';
        }

        $_SESSION['flash_' . $type] = $message;
        $_SESSION['admin_refund_flash'] = [
            'type' => $type,
            'message' => $message,
        ];
    }
}

if (!function_exists('bv_admin_refund_action_is_safe_return_url')) {
    function bv_admin_refund_action_is_safe_return_url(string $url): bool
    {
        $url = trim($url);
        if ($url === '') {
            return false;
        }

        if (preg_match('~^[a-z][a-z0-9+\-.]*://~i', $url)) {
            return false;
        }

        if (strpos($url, '//') === 0) {
            return false;
        }

        if (stripos($url, 'javascript:') === 0 || stripos($url, 'data:') === 0) {
            return false;
        }

        if (strpos($url, "\r") !== false || strpos($url, "\n") !== false) {
            return false;
        }

        return true;
    }
}

if (!function_exists('bv_admin_refund_action_redirect')) {
    function bv_admin_refund_action_redirect(string $default = '/admin/refunds.php'): void
    {
        $returnUrl = isset($_POST['return_url']) ? (string) $_POST['return_url'] : '';
        if ($returnUrl === '') {
            $returnUrl = isset($_GET['return_url']) ? (string) $_GET['return_url'] : '';
        }

        if (!bv_admin_refund_action_is_safe_return_url($returnUrl)) {
            $returnUrl = $default;
        }

        header('Location: ' . $returnUrl);
        exit;
    }
}

if (!function_exists('bv_admin_refund_action_verify_csrf')) {
    function bv_admin_refund_action_verify_csrf(): bool
    {
        $posted = (string) ($_POST['csrf_token'] ?? '');

        $candidates = [];

        if (isset($_SESSION['_csrf_admin_refunds']['refund_actions']) && is_string($_SESSION['_csrf_admin_refunds']['refund_actions'])) {
            $candidates[] = (string) $_SESSION['_csrf_admin_refunds']['refund_actions'];
        }
        if (isset($_SESSION['_csrf_admin_refunds']['admin_refund_actions']) && is_string($_SESSION['_csrf_admin_refunds']['admin_refund_actions'])) {
            $candidates[] = (string) $_SESSION['_csrf_admin_refunds']['admin_refund_actions'];
        }
        if (isset($_SESSION['csrf_token']) && is_string($_SESSION['csrf_token'])) {
            $candidates[] = (string) $_SESSION['csrf_token'];
        }

        $candidates = array_values(array_filter(array_unique($candidates), static function ($v) {
            return is_string($v) && $v !== '';
        }));

        if ($candidates === []) {
            return true;
        }

        if ($posted === '') {
            return false;
        }

        foreach ($candidates as $token) {
            if (hash_equals($token, $posted)) {
                return true;
            }
        }

        return false;
    }
}

if (!function_exists('bv_admin_refund_action_actor_user_id')) {
    function bv_admin_refund_action_actor_user_id(): int
    {
        try {
            $id = bv_order_refund_current_user_id();
            return $id > 0 ? $id : 0;
        } catch (Throwable $e) {
            return 0;
        }
    }
}

if (!function_exists('bv_admin_refund_action_actor_role')) {
    function bv_admin_refund_action_actor_role(): string
    {
        try {
            $role = strtolower(trim((string) bv_order_refund_current_user_role()));
            return $role !== '' ? $role : 'admin';
        } catch (Throwable $e) {
            return 'admin';
        }
    }
}

if (!function_exists('bv_admin_refund_action_amount')) {
    function bv_admin_refund_action_amount(string $field): float
    {
        $raw = $_POST[$field] ?? 0;
        if (!is_numeric($raw)) {
            return 0.0;
        }

        $amount = round((float) $raw, 2);
        return $amount > 0 ? $amount : 0.0;
    }
}

if (!function_exists('bv_admin_refund_action_safe_note')) {
    function bv_admin_refund_action_safe_note(string $field, string $fallback = ''): string
    {
        $value = trim((string) ($_POST[$field] ?? ''));
        return $value !== '' ? $value : $fallback;
    }
}

if (!function_exists('bv_admin_refund_action_get_refund')) {
    function bv_admin_refund_action_get_refund(int $refundId): array
    {
        $refund = bv_order_refund_get_by_id($refundId);
        if (!$refund) {
            throw new RuntimeException('Refund not found.');
        }

        return $refund;
    }
}

if (!function_exists('bv_admin_refund_action_remaining_amount')) {
    function bv_admin_refund_action_remaining_amount(array $refund): float
    {
        $target = 0.0;

        if (isset($refund['actual_refund_amount']) && is_numeric($refund['actual_refund_amount'])) {
            $target = round((float) $refund['actual_refund_amount'], 2);
        }

        if ($target <= 0 && isset($refund['approved_refund_amount']) && is_numeric($refund['approved_refund_amount'])) {
            $target = round((float) $refund['approved_refund_amount'], 2);
        }

        $already = isset($refund['actual_refunded_amount']) && is_numeric($refund['actual_refunded_amount'])
            ? round((float) $refund['actual_refunded_amount'], 2)
            : 0.0;

        $remaining = round($target - $already, 2);
        return $remaining > 0 ? $remaining : 0.0;
    }
}

if (!function_exists('bv_admin_refund_action_build_stripe_payload')) {
    function bv_admin_refund_action_build_stripe_payload(int $refundId, array $refund, float $amount): array
    {
        $paymentIntentId = trim((string) ($_POST['payment_intent_id'] ?? ''));
        $chargeId = trim((string) ($_POST['charge_id'] ?? ''));

        if ($paymentIntentId === '') {
            $paymentIntentId = trim((string) ($refund['payment_reference_snapshot'] ?? ''));
        }

        return [
            'refund_id' => $refundId,
            'payment_intent_id' => $paymentIntentId,
            'charge_id' => $chargeId,
            'amount' => $amount,
            'currency' => (string) ($refund['currency'] ?? 'USD'),
            'reason' => (string) ($_POST['reason'] ?? 'requested_by_customer'),
            'metadata' => [
                'refund_id' => (string) $refundId,
                'order_id' => (string) ($refund['order_id'] ?? 0),
                'refund_code' => (string) ($refund['refund_code'] ?? ''),
                'source' => 'admin_refund_action',
            ],
        ];
    }
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    bv_admin_refund_action_set_flash('error', 'Invalid request method.');
    bv_admin_refund_action_redirect();
}

if (!bv_admin_refund_action_verify_csrf()) {
    bv_admin_refund_action_set_flash('error', 'Invalid CSRF token.');
    bv_admin_refund_action_redirect();
}

$action = strtolower(trim((string) ($_POST['action'] ?? '')));
$refundId = isset($_POST['refund_id']) && is_numeric($_POST['refund_id']) ? (int) $_POST['refund_id'] : 0;

if ($refundId <= 0 || $action === '') {
    bv_admin_refund_action_set_flash('error', 'Missing refund action data.');
    bv_admin_refund_action_redirect();
}

$actorUserId = bv_admin_refund_action_actor_user_id();
$actorRole = bv_admin_refund_action_actor_role();

try {
    if ($action === 'approve') {
        $refund = bv_admin_refund_action_get_refund($refundId);
        $approvedAmount = bv_admin_refund_action_amount('approved_amount');
        if ($approvedAmount <= 0) {
            $approvedAmount = isset($refund['requested_refund_amount']) && is_numeric($refund['requested_refund_amount'])
                ? round((float) $refund['requested_refund_amount'], 2)
                : 0.0;
        }
        if ($approvedAmount <= 0) {
            throw new RuntimeException('Approved refund amount must be greater than zero.');
        }

        bv_order_refund_approve(
            $refundId,
            $approvedAmount,
            $actorUserId,
            $actorRole,
            bv_admin_refund_action_safe_note('note')
        );

        bv_admin_refund_action_set_flash('success', 'Refund approved.');
    } elseif ($action === 'reject') {
        bv_order_refund_reject(
            $refundId,
            bv_admin_refund_action_safe_note('reason'),
            $actorUserId,
            $actorRole
        );

        bv_admin_refund_action_set_flash('success', 'Refund rejected.');
    } elseif ($action === 'cancel') {
        bv_order_refund_cancel(
            $refundId,
            bv_admin_refund_action_safe_note('reason'),
            $actorUserId,
            $actorRole
        );

        bv_admin_refund_action_set_flash('success', 'Refund cancelled.');
    } elseif ($action === 'processing') {
        bv_order_refund_mark_processing(
            $refundId,
            $actorUserId,
            bv_admin_refund_action_safe_note('note'),
            $actorRole
        );

        bv_admin_refund_action_set_flash('success', 'Refund marked processing.');
    } elseif ($action === 'mark_failed') {
        bv_order_refund_mark_failed(
            $refundId,
            bv_admin_refund_action_safe_note('reason', 'Refund marked failed by admin'),
            [],
            $actorUserId,
            $actorRole
        );

        bv_admin_refund_action_set_flash('success', 'Refund marked failed.');
    } elseif ($action === 'mark_refunded_manual') {
        $refund = bv_admin_refund_action_get_refund($refundId);
        $remaining = bv_admin_refund_action_remaining_amount($refund);
        if ($remaining <= 0) {
            throw new RuntimeException('Nothing left to refund.');
        }

        $amount = bv_admin_refund_action_amount('actual_amount');
        if ($amount <= 0) {
            $amount = $remaining;
        }
        if ($amount > $remaining) {
            throw new RuntimeException('Manual refunded amount exceeds remaining refundable amount.');
        }

        bv_order_refund_mark_refunded(
            $refundId,
            $amount,
            [],
            $actorUserId,
            bv_admin_refund_action_safe_note('note', 'Manual refund'),
            $actorRole
        );

        bv_admin_refund_action_set_flash('success', 'Refund marked refunded.');
    } elseif ($action === 'refund_stripe') {
        $refund = bv_admin_refund_action_get_refund($refundId);
        $status = strtolower(trim((string) ($refund['status'] ?? '')));

        if (!in_array($status, ['approved', 'processing', 'partially_refunded'], true)) {
            throw new RuntimeException('Refund is not in a Stripe-processable status.');
        }

        $remainingRefundable = bv_admin_refund_action_remaining_amount($refund);
        if ($remainingRefundable <= 0) {
            bv_admin_refund_action_set_flash('success', 'Refund already fully refunded.');
            bv_admin_refund_action_redirect();
        }

        $requestedAmount = bv_admin_refund_action_amount('amount');
        $amount = $requestedAmount > 0 ? $requestedAmount : $remainingRefundable;

        if ($amount <= 0) {
            throw new RuntimeException('Refund amount must be greater than zero.');
        }
        if ($amount > $remainingRefundable) {
            throw new RuntimeException('Refund amount exceeds remaining refundable amount.');
        }

        if ($status !== 'processing') {
            bv_order_refund_mark_processing(
                $refundId,
                $actorUserId,
                'Stripe refund initiated by admin',
                $actorRole
            );
            $refund = bv_admin_refund_action_get_refund($refundId);
        }

        $stripeResult = bv_stripe_refund_create(
            bv_admin_refund_action_build_stripe_payload($refundId, $refund, $amount)
        );

        bv_order_refund_insert_transaction([
            'refund_id' => $refundId,
            'transaction_type' => 'provider_refund',
            'transaction_status' => (string) ($stripeResult['transaction_status'] ?? 'pending'),
            'provider' => 'stripe',
            'provider_refund_id' => (string) ($stripeResult['provider_refund_id'] ?? ''),
            'provider_payment_intent_id' => (string) ($stripeResult['provider_payment_intent_id'] ?? ''),
            'currency' => (string) ($stripeResult['currency'] ?? ($refund['currency'] ?? 'USD')),
            'amount' => (float) ($stripeResult['amount'] ?? $amount),
            'raw_request_payload' => (string) ($stripeResult['raw_request_payload'] ?? ''),
            'raw_response_payload' => (string) ($stripeResult['raw_response_payload'] ?? ''),
            'failure_code' => (string) ($stripeResult['failure_code'] ?? ''),
            'failure_message' => (string) ($stripeResult['failure_message'] ?? ''),
            'created_by_user_id' => $actorUserId,
        ]);

        $normalized = strtolower(trim((string) ($stripeResult['transaction_status'] ?? 'pending')));

        if ($normalized === 'succeeded') {
            bv_order_refund_mark_refunded(
                $refundId,
                $amount,
                [],
                $actorUserId,
                'Stripe refund succeeded',
                $actorRole
            );
            bv_admin_refund_action_set_flash('success', 'Stripe refund succeeded.');
        } elseif ($normalized === 'failed' || $normalized === 'cancelled') {
            bv_order_refund_mark_failed(
                $refundId,
                (string) ($stripeResult['failure_message'] ?? 'Stripe refund failed'),
                [],
                $actorUserId,
                $actorRole
            );
            bv_admin_refund_action_set_flash('error', 'Stripe refund failed.');
        } else {
            bv_admin_refund_action_set_flash('success', 'Stripe refund pending.');
        }
    } else {
        throw new RuntimeException('Unsupported action: ' . $action);
    }
} catch (Throwable $e) {
    bv_admin_refund_action_set_flash('error', $e->getMessage());
}

bv_admin_refund_action_redirect();