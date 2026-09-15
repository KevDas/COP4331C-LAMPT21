<?php
// ============================================================
//  api_contacts/config/helpers.php — Utility & Helper Functions for API
// ============================================================

/**
 * Loads environment variables from a .env file into putenv, $_ENV, and $_SERVER.
 *
 * @param string|null $path Path to the .env file
 */
function loadEnv($path = null) {
    static $loaded = false;
    if ($loaded) {
        return;
    }

    if ($path === null) {
        $possiblePaths = [
            __DIR__ . '/../../.env',
            __DIR__ . '/../.env',
            __DIR__ . '/.env',
            (defined('ROOT_PATH') ? ROOT_PATH . '/.env' : null),
        ];
        foreach ($possiblePaths as $p) {
            if ($p && file_exists($p)) {
                $path = $p;
                break;
            }
        }
    }

    if ($path && file_exists($path)) {
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || str_starts_with($line, '#')) {
                continue;
            }
            if (strpos($line, '=') !== false) {
                list($name, $value) = explode('=', $line, 2);
                $name  = trim($name);
                $value = trim($value);

                if ((str_starts_with($value, '"') && str_ends_with($value, '"')) ||
                    (str_starts_with($value, "'") && str_ends_with($value, "'"))) {
                    $value = substr($value, 1, -1);
                }

                if (getenv($name) === false) {
                    putenv("{$name}={$value}");
                    $_ENV[$name] = $value;
                    $_SERVER[$name] = $value;
                }
            }
        }
    }
    $loaded = true;
}

loadEnv();

/**
 * Sets standard CORS headers to allow cross-origin API requests.
 * Handles preflight OPTIONS requests by exiting with 200 OK.
 */
function setCORSHeaders() {
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-User-Id");

    if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit;
    }
}

/**
 * Sends a JSON response with the specified HTTP status code and terminates execution.
 *
 * @param int $statusCode HTTP status code
 * @param mixed $data Data array or object to serialize as JSON
 */
function respond($statusCode, $data) {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data);
    exit;
}

/**
 * Gets and decodes the JSON request body or falls back to $_POST input.
 *
 * @return array
 */
function getRequestBody() {
    $rawInput = file_get_contents('php://input');
    if (!empty($rawInput)) {
        $decoded = json_decode($rawInput, true);
        if (is_array($decoded)) {
            return $decoded;
        }
    }
    return $_POST ?? [];
}

/**
 * Sanitizes input data by trimming whitespace and stripping HTML tags.
 *
 * @param mixed $data
 * @return mixed
 */
function clean($data) {
    if (is_string($data)) {
        return trim(strip_tags($data));
    }
    return $data;
}

/**
 * Hash a plaintext password for storage.
 *
 * @param string $password
 * @return string
 */
function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

/**
 * Verify a plaintext password against a stored hash.
 *
 * @param string $password
 * @param string $hash
 * @return bool
 */
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

/**
 * Resolves a numeric user ID from headers, cookies, session, query, or body.
 *
 * @return int|null
 */
function resolveAuthUserId() {
    $userId = null;

    $authHeader = $_SERVER['HTTP_AUTHORIZATION']
        ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
        ?? (function_exists('apache_request_headers') ? (apache_request_headers()['Authorization'] ?? null) : null);

    if ($authHeader) {
        $token = trim(preg_replace('/^Bearer\s+/i', '', $authHeader));
        if (is_numeric($token) && (int)$token > 0) {
            $userId = (int)$token;
        } else {
            $parts = explode('.', $token);
            if (count($parts) === 3) {
                $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
                if (is_array($payload)) {
                    $userId = $payload['userId'] ?? $payload['user_id'] ?? $payload['id'] ?? $payload['sub'] ?? null;
                }
            }
        }
    }

    if (!$userId) {
        $xUserId = $_SERVER['HTTP_X_USER_ID'] ?? $_SERVER['HTTP_USER_ID'] ?? null;
        if ($xUserId && is_numeric($xUserId) && (int)$xUserId > 0) {
            $userId = (int)$xUserId;
        }
    }

    if (!$userId && isset($_COOKIE['userId']) && is_numeric($_COOKIE['userId'])) {
        $userId = (int)$_COOKIE['userId'];
    } elseif (!$userId && isset($_COOKIE['user_id']) && is_numeric($_COOKIE['user_id'])) {
        $userId = (int)$_COOKIE['user_id'];
    }

    if (!$userId) {
        if (session_status() === PHP_SESSION_NONE && !headers_sent()) {
            @session_start();
        }
        if (isset($_SESSION['userId']) && is_numeric($_SESSION['userId'])) {
            $userId = (int)$_SESSION['userId'];
        } elseif (isset($_SESSION['user_id']) && is_numeric($_SESSION['user_id'])) {
            $userId = (int)$_SESSION['user_id'];
        }
    }

    if (!$userId) {
        $qUserId = $_GET['userId'] ?? $_GET['user_id'] ?? $_GET['uid'] ?? null;
        if ($qUserId && is_numeric($qUserId) && (int)$qUserId > 0) {
            $userId = (int)$qUserId;
        }
    }

    if (!$userId) {
        $body = getRequestBody();
        $bUserId = $body['userId'] ?? $body['user_id'] ?? $body['uid'] ?? null;
        if ($bUserId && is_numeric($bUserId) && (int)$bUserId > 0) {
            $userId = (int)$bUserId;
        }
    }

    return ($userId && (int)$userId > 0) ? (int)$userId : null;
}

/**
 * Requires authentication and returns the authenticated user row (no password).
 * Disabled accounts are rejected with 401.
 *
 * @return array
 */
function requireAuth() {
    $userId = resolveAuthUserId();
    if (!$userId) {
        respond(401, ['error' => 'Unauthorized']);
    }

    $db = getDB();
    $stmt = $db->prepare('SELECT ID, FirstName, LastName, Login, IsAdmin, Disabled FROM Users WHERE ID = :id LIMIT 1');
    $stmt->execute([':id' => $userId]);
    $user = $stmt->fetch();

    if (!$user) {
        respond(401, ['error' => 'Unauthorized']);
    }

    if ((int) $user['Disabled'] === 1) {
        respond(401, ['error' => 'Account disabled']);
    }

    return $user;
}

/**
 * Requires an authenticated admin user.
 *
 * @return array
 */
function requireAdmin() {
    $user = requireAuth();
    if ((int) $user['IsAdmin'] !== 1) {
        respond(403, ['error' => 'Forbidden']);
    }
    return $user;
}

/**
 * Public JSON shape for a user row (never includes password).
 *
 * @param array $row
 * @return array
 */
function formatUser($row) {
    return [
        'id'        => (int) $row['ID'],
        'firstName' => $row['FirstName'],
        'lastName'  => $row['LastName'],
        'login'     => $row['Login'],
        'isAdmin'   => (int) $row['IsAdmin'] === 1,
        'disabled'  => (int) $row['Disabled'] === 1,
    ];
}

/**
 * Public JSON shape for a contact row.
 *
 * @param array $row
 * @return array
 */
function formatContact($row) {
    return [
        'id'        => (int) $row['ID'],
        'userId'    => (int) $row['UserID'],
        'firstName' => $row['FirstName'],
        'lastName'  => $row['LastName'],
        'email'     => $row['Email'],
        'phone'     => $row['Phone'],
    ];
}

/**
 * Resolves the requested resource from PATH_INFO or ?resource=
 *
 * @return string
 */
function getResource() {
    $path = $_SERVER['PATH_INFO'] ?? '';
    $path = strtolower(trim($path, '/'));
    if ($path === '' && isset($_GET['resource'])) {
        $path = strtolower(trim((string) $_GET['resource'], '/'));
    }
    if ($path === '' && isset($_GET['action'])) {
        $path = strtolower(trim((string) $_GET['action'], '/'));
    }
    return $path;
}
