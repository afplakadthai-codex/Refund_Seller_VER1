<?php
// /seller/_guard.php

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

/**
 * โหลดไฟล์ตัวแรกที่เจอจากหลาย path
 */
if (!function_exists('seller_load_first_file')) {
    function seller_load_first_file(array $paths)
    {
        foreach ($paths as $path) {
            if (is_file($path)) {
                require_once $path;
                return $path;
            }
        }
        return null;
    }
}

/**
 * โหลด DB / config
 * ปรับลำดับ path ให้รองรับทั้ง includes และ include
 */
seller_load_first_file(array(
    __DIR__ . '/../includes/db.php',
    __DIR__ . '/../config/db.php',
    __DIR__ . '/../includes/config.php',
    __DIR__ . '/../config/config.php',
));

/**
 * โหลด auth หลักของระบบ
 * จากที่คุณแจ้ง auth.php ตัวจริงอยู่ที่ /include/auth.php
 * แต่ผมเผื่อ path สำรองไว้ให้ด้วย
 */
seller_load_first_file(array(
    __DIR__ . '/../include/auth.php',
    __DIR__ . '/../includes/auth.php',
));

/**
 * helper: จบการทำงานพร้อม status code
 */
if (!function_exists('seller_abort')) {
    function seller_abort($statusCode, $message)
    {
        http_response_code((int) $statusCode);
        echo $message;
        exit;
    }
}

/**
 * หา PDO ของระบบ
 */
if (!function_exists('seller_pdo')) {
    function seller_pdo()
    {
        global $pdo, $db;

        if (isset($pdo) && $pdo instanceof PDO) {
            return $pdo;
        }

        if (isset($db) && $db instanceof PDO) {
            return $db;
        }

        if (function_exists('get_pdo')) {
            $conn = get_pdo();
            if ($conn instanceof PDO) {
                return $conn;
            }
        }

        if (function_exists('db')) {
            $conn = db();
            if ($conn instanceof PDO) {
                return $conn;
            }
        }

        seller_abort(500, 'PDO connection not available in /seller/_guard.php');
    }
}

/**
 * ดึง current user id จาก session ให้ยืดหยุ่นกับหลายระบบ
 */
if (!function_exists('seller_current_user_id')) {
    function seller_current_user_id()
    {
        $candidates = array(
            isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null,
            isset($_SESSION['member_id']) ? $_SESSION['member_id'] : null,
            isset($_SESSION['auth_user_id']) ? $_SESSION['auth_user_id'] : null,
            isset($_SESSION['user']['id']) ? $_SESSION['user']['id'] : null,
            isset($_SESSION['member']['id']) ? $_SESSION['member']['id'] : null,
            isset($_SESSION['auth']['user_id']) ? $_SESSION['auth']['user_id'] : null,
        );

        foreach ($candidates as $value) {
            if ($value !== null && $value !== '' && ctype_digit((string) $value)) {
                return (int) $value;
            }
        }

        return 0;
    }
}

/**
 * redirect helper
 */
if (!function_exists('seller_redirect')) {
    function seller_redirect($url)
    {
        header('Location: ' . $url);
        exit;
    }
}

/**
 * บังคับ login
 * ถ้าระบบหลักมี require_login() ก็ใช้ของเดิม
 * ถ้าไม่มี ค่อย fallback เช็ก session เอง
 */
if (!function_exists('seller_require_login')) {
    function seller_require_login()
    {
        if (function_exists('require_login')) {
            require_login();
            return;
        }

        $userId = seller_current_user_id();
        if ($userId > 0) {
            return;
        }

        seller_redirect('/login.php');
    }
}

/**
 * ตรวจว่า user นี้เป็น seller หรือยัง
 * รองรับทั้ง role ใน users และ seller_applications
 */
if (!function_exists('seller_is_approved')) {
    function seller_is_approved($userId)
    {
        $userId = (int) $userId;
        if ($userId <= 0) {
            return false;
        }

        $pdo = seller_pdo();

        // 1) เช็ก role จาก users ก่อน
        try {
            $stmt = $pdo->prepare("
                SELECT role, account_status
                FROM users
                WHERE id = ?
                LIMIT 1
            ");
            $stmt->execute(array($userId));
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($row) {
                $role = isset($row['role']) ? (string) $row['role'] : '';
                $accountStatus = isset($row['account_status']) ? (string) $row['account_status'] : '';

                if ($role === 'seller' && ($accountStatus === '' || $accountStatus === 'active')) {
                    return true;
                }
            }
        } catch (Throwable $e) {
            // ข้ามไปเช็กตาราง seller_applications ต่อ
        } catch (Exception $e) {
            // PHP 7 compatibility
        }

        // 2) เช็กใบสมัคร seller
        try {
            $stmt = $pdo->prepare("
                SELECT application_status
                FROM seller_applications
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT 1
            ");
            $stmt->execute(array($userId));
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($row) {
                $status = isset($row['application_status']) ? (string) $row['application_status'] : '';
                return $status === 'approved';
            }
        } catch (Throwable $e) {
            return false;
        } catch (Exception $e) {
            return false;
        }

        return false;
    }
}

/**
 * กันหน้า seller: ต้อง login + ต้องเป็น seller ที่ approved แล้ว
 */
if (!function_exists('seller_guard')) {
    function seller_guard()
    {
        seller_require_login();

        $userId = seller_current_user_id();
        if ($userId <= 0) {
            seller_redirect('/login.php');
        }

        if (!seller_is_approved($userId)) {
            seller_redirect('/seller/apply.php');
        }

        return $userId;
    }
}

/**
 * เรียกใช้งานทันทีเมื่อ include ไฟล์นี้
 */
$currentSellerUserId = seller_guard();