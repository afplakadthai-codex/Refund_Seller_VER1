<?php
declare(strict_types=1);

/**
 * config/db.php
 * Direct DB connection (PDO)
 */

if (!defined('DB_HOST')) {
    define('DB_HOST', 'localhost');
}

if (!defined('DB_NAME')) {
    define('DB_NAME', 'saladfa1_bettavaro');
}

if (!defined('DB_USER')) {
    define('DB_USER', 'saladfa1_bettavaro_admin');
}

if (!defined('DB_PASS')) {
    define('DB_PASS', 'Admin_Bettavaro_Webmaster_Athchara@080418');
}

if (!defined('DB_CHARSET')) {
    define('DB_CHARSET', 'utf8mb4');
}

if (!function_exists('db')) {
    function db(): PDO
    {
        static $pdo = null;

        if ($pdo instanceof PDO) {
            return $pdo;
        }

        $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET;

        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];

        $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        return $pdo;
    }
}

/**
 * เผื่อไฟล์เก่าบางตัวใช้ตัวแปร $pdo ตรง ๆ
 */
try {
    $pdo = db();
	$GLOBALS['pdo'] = $pdo;
} catch (Throwable $e) {
    http_response_code(500);
    exit('Database connection failed: ' . $e->getMessage());
}
?>