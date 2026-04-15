<?php
declare(strict_types=1);

if (!function_exists('bv_stripe_refund_boot')) {
    function bv_stripe_refund_boot(): bool
    {
        if (!isset($GLOBALS['bv_stripe_refund_booted'])) {
            $GLOBALS['bv_stripe_refund_booted'] = true;

            $paths = [
                __DIR__ . '/stripe.php',
                __DIR__ . '/stripe_config.php',
                dirname(__DIR__) . '/config/stripe.php',
                dirname(__DIR__) . '/includes/stripe.php',
                dirname(__DIR__) . '/includes/stripe_config.php',
            ];

            foreach ($paths as $path) {
                if (is_file($path)) {
                    require_once $path;
                }
            }
        }

        return true;
    }
}

if (!function_exists('bv_stripe_refund_env')) {
    function bv_stripe_refund_env(string $key, string $default = ''): string
    {
        $value = getenv($key);
        if ($value === false || $value === null) {
            return $default;
        }

        $value = trim((string) $value);
        return $value !== '' ? $value : $default;
    }
}

if (!function_exists('bv_stripe_refund_pick_first_non_empty')) {
    function bv_stripe_refund_pick_first_non_empty(array $values, string $default = ''): string
    {
        foreach ($values as $value) {
            if (!is_string($value) && !is_numeric($value)) {
                continue;
            }

            $value = trim((string) $value);
            if ($value !== '') {
                return $value;
            }
        }

        return $default;
    }
}

if (!function_exists('bv_stripe_refund_detect_mode')) {
    function bv_stripe_refund_detect_mode(): string
    {
        $candidates = [
            $GLOBALS['BV_STRIPE_MODE'] ?? null,
            $GLOBALS['bv_stripe_mode'] ?? null,
            $GLOBALS['stripe_mode'] ?? null,
            $GLOBALS['STRIPE_MODE'] ?? null,
            bv_stripe_refund_env('BV_STRIPE_MODE'),
            bv_stripe_refund_env('STRIPE_MODE'),
        ];

        foreach ($candidates as $candidate) {
            $mode = strtolower(trim((string) $candidate));
            if ($mode === 'test') {
                return 'test';
            }
            if ($mode === 'live') {
                return 'live';
            }
        }

        return 'live';
    }
}

if (!function_exists('bv_stripe_refund_guess_mode_from_key')) {
    function bv_stripe_refund_guess_mode_from_key(string $secretKey, string $fallback = 'live'): string
    {
        $secretKey = trim($secretKey);
        if ($secretKey === '') {
            return $fallback;
        }

        if (strpos($secretKey, 'sk_test_') === 0) {
            return 'test';
        }

        if (strpos($secretKey, 'sk_live_') === 0) {
            return 'live';
        }

        return $fallback;
    }
}

if (!function_exists('bv_stripe_refund_config')) {
    function bv_stripe_refund_config(): array
    {
        bv_stripe_refund_boot();

        $mode = bv_stripe_refund_detect_mode();

        $sources = [
            $GLOBALS['stripe'] ?? null,
            $GLOBALS['stripe_config'] ?? null,
            $GLOBALS['config']['stripe'] ?? null,
            $GLOBALS['settings']['stripe'] ?? null,
        ];

        $modeAwareSecret = '';
        $modeAwarePublishable = '';
        $modeAwareWebhook = '';

        foreach ($sources as $source) {
            if (!is_array($source)) {
                continue;
            }

            if ($mode === 'test') {
                $modeAwareSecret = bv_stripe_refund_pick_first_non_empty([
                    $modeAwareSecret,
                    $source['test_secret_key'] ?? '',
                    $source['secret_key_test'] ?? '',
                    $source['sk_test'] ?? '',
                ]);
                $modeAwarePublishable = bv_stripe_refund_pick_first_non_empty([
                    $modeAwarePublishable,
                    $source['test_publishable_key'] ?? '',
                    $source['publishable_key_test'] ?? '',
                    $source['pk_test'] ?? '',
                ]);
                $modeAwareWebhook = bv_stripe_refund_pick_first_non_empty([
                    $modeAwareWebhook,
                    $source['test_webhook_secret'] ?? '',
                    $source['webhook_secret_test'] ?? '',
                    $source['endpoint_secret_test'] ?? '',
                ]);
            } else {
                $modeAwareSecret = bv_stripe_refund_pick_first_non_empty([
                    $modeAwareSecret,
                    $source['live_secret_key'] ?? '',
                    $source['secret_key_live'] ?? '',
                    $source['sk_live'] ?? '',
                ]);
                $modeAwarePublishable = bv_stripe_refund_pick_first_non_empty([
                    $modeAwarePublishable,
                    $source['live_publishable_key'] ?? '',
                    $source['publishable_key_live'] ?? '',
                    $source['pk_live'] ?? '',
                ]);
                $modeAwareWebhook = bv_stripe_refund_pick_first_non_empty([
                    $modeAwareWebhook,
                    $source['live_webhook_secret'] ?? '',
                    $source['webhook_secret_live'] ?? '',
                    $source['endpoint_secret_live'] ?? '',
                ]);
            }
        }

        $genericSecret = '';
        $genericPublishable = '';
        $genericWebhook = '';

        foreach ($sources as $source) {
            if (!is_array($source)) {
                continue;
            }

            $genericSecret = bv_stripe_refund_pick_first_non_empty([
                $genericSecret,
                $source['secret_key'] ?? '',
                $source['secret'] ?? '',
                $source['sk'] ?? '',
            ]);

            $genericPublishable = bv_stripe_refund_pick_first_non_empty([
                $genericPublishable,
                $source['publishable_key'] ?? '',
                $source['publishable'] ?? '',
                $source['pk'] ?? '',
            ]);

            $genericWebhook = bv_stripe_refund_pick_first_non_empty([
                $genericWebhook,
                $source['webhook_secret'] ?? '',
                $source['endpoint_secret'] ?? '',
            ]);
        }

        if ($mode === 'test') {
            $envSecret = bv_stripe_refund_pick_first_non_empty([
                bv_stripe_refund_env('STRIPE_TEST_SECRET_KEY'),
                bv_stripe_refund_env('BV_STRIPE_TEST_SECRET_KEY'),
                bv_stripe_refund_env('STRIPE_SECRET_KEY'),
                bv_stripe_refund_env('BV_STRIPE_SECRET_KEY'),
            ]);
            $envPublishable = bv_stripe_refund_pick_first_non_empty([
                bv_stripe_refund_env('STRIPE_TEST_PUBLISHABLE_KEY'),
                bv_stripe_refund_env('BV_STRIPE_TEST_PUBLISHABLE_KEY'),
                bv_stripe_refund_env('STRIPE_PUBLISHABLE_KEY'),
                bv_stripe_refund_env('BV_STRIPE_PUBLISHABLE_KEY'),
            ]);
            $envWebhook = bv_stripe_refund_pick_first_non_empty([
                bv_stripe_refund_env('STRIPE_TEST_WEBHOOK_SECRET'),
                bv_stripe_refund_env('BV_STRIPE_TEST_WEBHOOK_SECRET'),
                bv_stripe_refund_env('STRIPE_WEBHOOK_SECRET'),
                bv_stripe_refund_env('BV_STRIPE_WEBHOOK_SECRET'),
            ]);
        } else {
            $envSecret = bv_stripe_refund_pick_first_non_empty([
                bv_stripe_refund_env('STRIPE_LIVE_SECRET_KEY'),
                bv_stripe_refund_env('BV_STRIPE_LIVE_SECRET_KEY'),
                bv_stripe_refund_env('STRIPE_SECRET_KEY'),
                bv_stripe_refund_env('BV_STRIPE_SECRET_KEY'),
            ]);
            $envPublishable = bv_stripe_refund_pick_first_non_empty([
                bv_stripe_refund_env('STRIPE_LIVE_PUBLISHABLE_KEY'),
                bv_stripe_refund_env('BV_STRIPE_LIVE_PUBLISHABLE_KEY'),
                bv_stripe_refund_env('STRIPE_PUBLISHABLE_KEY'),
                bv_stripe_refund_env('BV_STRIPE_PUBLISHABLE_KEY'),
            ]);
            $envWebhook = bv_stripe_refund_pick_first_non_empty([
                bv_stripe_refund_env('STRIPE_LIVE_WEBHOOK_SECRET'),
                bv_stripe_refund_env('BV_STRIPE_LIVE_WEBHOOK_SECRET'),
                bv_stripe_refund_env('STRIPE_WEBHOOK_SECRET'),
                bv_stripe_refund_env('BV_STRIPE_WEBHOOK_SECRET'),
            ]);
        }

        $secret = bv_stripe_refund_pick_first_non_empty([
            $modeAwareSecret,
            $genericSecret,
            $GLOBALS['stripe_secret_key'] ?? '',
            $GLOBALS['STRIPE_SECRET_KEY'] ?? '',
            $envSecret,
        ]);

        $publishable = bv_stripe_refund_pick_first_non_empty([
            $modeAwarePublishable,
            $genericPublishable,
            $GLOBALS['stripe_publishable_key'] ?? '',
            $GLOBALS['STRIPE_PUBLISHABLE_KEY'] ?? '',
            $envPublishable,
        ]);

        $webhookSecret = bv_stripe_refund_pick_first_non_empty([
            $modeAwareWebhook,
            $genericWebhook,
            $GLOBALS['stripe_webhook_secret'] ?? '',
            $GLOBALS['STRIPE_WEBHOOK_SECRET'] ?? '',
            $envWebhook,
        ]);

        if ($secret === '') {
            throw new RuntimeException('Stripe configuration missing: secret key not found.');
        }

        $mode = bv_stripe_refund_guess_mode_from_key($secret, $mode);

        return [
            'secret_key' => $secret,
            'publishable_key' => $publishable,
            'webhook_secret' => $webhookSecret,
            'mode' => $mode,
            'api_base' => 'https://api.stripe.com/v1',
        ];
    }
}

if (!function_exists('bv_stripe_refund_client')) {
    function bv_stripe_refund_client(): array
    {
        return bv_stripe_refund_config();
    }
}

if (!function_exists('bv_stripe_refund_build_idempotency_key')) {
    function bv_stripe_refund_build_idempotency_key(int $refundId, float $amount): string
    {
        if ($refundId <= 0) {
            throw new InvalidArgumentException('refundId must be positive.');
        }

        $amount = round($amount, 2);

        return 'bv-refund-' . $refundId . '-' . str_replace('.', '_', (string) $amount);
    }
}

if (!function_exists('bv_stripe_refund_extract_reference')) {
    function bv_stripe_refund_extract_reference(array $stripeRefund): string
    {
        if (!empty($stripeRefund['id'])) {
            return (string) $stripeRefund['id'];
        }

        return (string) ($stripeRefund['object'] ?? '');
    }
}

if (!function_exists('bv_stripe_refund_normalize_status')) {
    function bv_stripe_refund_normalize_status($status): string
    {
        $status = strtolower(trim((string) $status));

        if ($status === 'succeeded') {
            return 'succeeded';
        }

        if ($status === 'failed') {
            return 'failed';
        }

        if ($status === 'canceled' || $status === 'cancelled') {
            return 'cancelled';
        }

        if ($status === 'pending' || $status === 'requires_action') {
            return 'pending';
        }

        return 'pending';
    }
}

if (!function_exists('bv_stripe_refund_is_zero_decimal_currency')) {
    function bv_stripe_refund_is_zero_decimal_currency(string $currency): bool
    {
        static $zeroDecimalCurrencies = [
            'bif', 'clp', 'djf', 'gnf', 'jpy', 'kmf', 'krw', 'mga',
            'pyg', 'rwf', 'ugx', 'vnd', 'vuv', 'xaf', 'xof', 'xpf',
        ];

        return in_array(strtolower(trim($currency)), $zeroDecimalCurrencies, true);
    }
}

if (!function_exists('bv_stripe_refund_amount_to_minor')) {
    function bv_stripe_refund_amount_to_minor(float $amountMajor, string $currency): int
    {
        $amountMajor = round($amountMajor, 2);

        if (bv_stripe_refund_is_zero_decimal_currency($currency)) {
            return (int) round($amountMajor);
        }

        return (int) round($amountMajor * 100);
    }
}

if (!function_exists('bv_stripe_refund_safe_json')) {
    function bv_stripe_refund_safe_json($value): string
    {
        $json = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        return is_string($json) ? $json : '{}';
    }
}

if (!function_exists('bv_stripe_refund_log')) {
    function bv_stripe_refund_log(string $message, array $context = []): void
    {
        try {
            $base = dirname(__DIR__);
            $paths = [
                $base . '/logs/stripe_refund.log',
                $base . '/private_html/logs/stripe_refund.log',
                dirname($base) . '/logs/stripe_refund.log',
                sys_get_temp_dir() . '/stripe_refund.log',
            ];

            $line = date('Y-m-d H:i:s') . ' ' . trim($message);
            if ($context !== []) {
                if (isset($context['secret_key'])) {
                    $context['secret_key'] = '[redacted]';
                }
                if (isset($context['Authorization'])) {
                    $context['Authorization'] = '[redacted]';
                }
                $line .= ' ' . bv_stripe_refund_safe_json($context);
            }
            $line .= PHP_EOL;

            foreach ($paths as $path) {
                $dir = dirname($path);
                if (!is_dir($dir)) {
                    @mkdir($dir, 0775, true);
                }

                if (@file_put_contents($path, $line, FILE_APPEND | LOCK_EX) !== false) {
                    return;
                }
            }
        } catch (Throwable $e) {
            // no-op
        }
    }
}

if (!function_exists('bv_stripe_refund_create')) {
    function bv_stripe_refund_create(array $data): array
    {
        $cfg = bv_stripe_refund_client();

        if (!function_exists('curl_init')) {
            throw new RuntimeException('cURL extension is not available for Stripe refund.');
        }

        $refundId = isset($data['refund_id']) ? (int) $data['refund_id'] : 0;
        if ($refundId <= 0) {
            throw new InvalidArgumentException('refund_id is required.');
        }

        $amountMajor = isset($data['amount']) ? (float) $data['amount'] : 0.0;
        if ($amountMajor <= 0) {
            throw new InvalidArgumentException('amount must be greater than zero.');
        }
        $amountMajor = round($amountMajor, 2);

        $currency = strtolower(trim((string) ($data['currency'] ?? 'usd')));
        if ($currency === '') {
            $currency = 'usd';
        }

        $amountMinor = bv_stripe_refund_amount_to_minor($amountMajor, $currency);

        $payload = [
            'amount' => $amountMinor,
            'currency' => $currency,
        ];

        $paymentIntentId = trim((string) ($data['payment_intent_id'] ?? ''));
        $chargeId = trim((string) ($data['charge_id'] ?? ''));

        if ($paymentIntentId !== '') {
            $payload['payment_intent'] = $paymentIntentId;
        } elseif ($chargeId !== '') {
            $payload['charge'] = $chargeId;
        } else {
            throw new InvalidArgumentException('payment_intent_id or charge_id is required for Stripe refund.');
        }

        $reason = trim((string) ($data['reason'] ?? 'requested_by_customer'));
        if ($reason !== '') {
            $payload['reason'] = $reason;
        }

        $metadata = is_array($data['metadata'] ?? null) ? $data['metadata'] : [];
        $metadata['refund_id'] = (string) $refundId;

        $postFields = [];
        foreach ($payload as $key => $value) {
            $postFields[$key] = (string) $value;
        }
        foreach ($metadata as $key => $value) {
            $postFields['metadata[' . $key . ']'] = (string) $value;
        }

        $idempotencyKey = bv_stripe_refund_build_idempotency_key($refundId, $amountMajor);
        $rawRequestPayload = http_build_query($postFields);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => rtrim((string) $cfg['api_base'], '/') . '/refunds',
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 60,
            CURLOPT_CONNECTTIMEOUT => 20,
            CURLOPT_POSTFIELDS => $rawRequestPayload,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $cfg['secret_key'],
                'Idempotency-Key: ' . $idempotencyKey,
                'Content-Type: application/x-www-form-urlencoded',
            ],
        ]);

        $rawResponse = curl_exec($ch);
        $curlErr = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $decoded = is_string($rawResponse) ? json_decode($rawResponse, true) : null;
        if (!is_array($decoded)) {
            $decoded = [];
        }

        if ($curlErr !== '') {
            bv_stripe_refund_log('stripe_refund_curl_error', [
                'refund_id' => $refundId,
                'error' => $curlErr,
                'http_code' => $httpCode,
            ]);

            return [
                'provider' => 'stripe',
                'provider_refund_id' => '',
                'provider_payment_intent_id' => $paymentIntentId,
                'provider_charge_id' => $chargeId,
                'amount' => $amountMajor,
                'currency' => strtoupper($currency),
                'raw_request_payload' => $rawRequestPayload,
                'raw_response_payload' => is_string($rawResponse) ? $rawResponse : '',
                'transaction_status' => 'failed',
                'stripe_status' => 'failed',
                'failure_code' => 'curl_error',
                'failure_message' => $curlErr,
                'http_code' => $httpCode,
            ];
        }

        $stripeStatusRaw = (string) ($decoded['status'] ?? '');
        if (isset($decoded['error']) && is_array($decoded['error'])) {
            $stripeStatusRaw = 'failed';
        }

        $normalizedStatus = bv_stripe_refund_normalize_status($stripeStatusRaw);
        if ($httpCode >= 400) {
            $normalizedStatus = 'failed';
        }

        $providerRefundId = (string) ($decoded['id'] ?? '');
        $providerPaymentIntentId = (string) ($decoded['payment_intent'] ?? $paymentIntentId);
        $providerChargeId = (string) ($decoded['charge'] ?? $chargeId);

        $failureCode = '';
        $failureMessage = '';

        if (isset($decoded['failure_reason'])) {
            $failureCode = (string) $decoded['failure_reason'];
        }

        if (isset($decoded['error']) && is_array($decoded['error'])) {
            $failureCode = (string) ($decoded['error']['code'] ?? $failureCode);
            $failureMessage = (string) ($decoded['error']['message'] ?? 'Stripe API error');
        }

        if ($failureMessage === '' && isset($decoded['failure_balance_transaction']) && $normalizedStatus === 'failed') {
            $failureMessage = 'Stripe refund failed.';
        }

        bv_stripe_refund_log('stripe_refund_response', [
            'refund_id' => $refundId,
            'mode' => (string) ($cfg['mode'] ?? 'live'),
            'http_code' => $httpCode,
            'status' => $normalizedStatus,
            'provider_refund_id' => $providerRefundId,
            'provider_payment_intent_id' => $providerPaymentIntentId,
            'provider_charge_id' => $providerChargeId,
        ]);

        return [
            'provider' => 'stripe',
            'provider_refund_id' => $providerRefundId,
            'provider_payment_intent_id' => $providerPaymentIntentId,
            'provider_charge_id' => $providerChargeId,
            'amount' => $amountMajor,
            'currency' => strtoupper((string) ($decoded['currency'] ?? $currency)),
            'raw_request_payload' => $rawRequestPayload,
            'raw_response_payload' => is_string($rawResponse) ? $rawResponse : '',
            'transaction_status' => $normalizedStatus,
            'stripe_status' => $stripeStatusRaw !== '' ? $stripeStatusRaw : $normalizedStatus,
            'failure_code' => $failureCode,
            'failure_message' => $failureMessage,
            'http_code' => $httpCode,
        ];
    }
}