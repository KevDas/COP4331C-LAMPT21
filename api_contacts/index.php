<?php
// ============================================================
//  api_contacts/index.php — Contact Manager RESTful API
//
//  GET    /api_contacts/index.php/ping
//  POST   /api_contacts/index.php/register
//  POST   /api_contacts/index.php/login
//  GET    /api_contacts/index.php/contacts
//  GET    /api_contacts/index.php/contacts?q=term
//  GET    /api_contacts/index.php/contacts?id=1
//  GET    /api_contacts/index.php/contacts?userId=3     (admin)
//  POST   /api_contacts/index.php/contacts
//  PUT    /api_contacts/index.php/contacts?id=1
//  DELETE /api_contacts/index.php/contacts?id=1
//  GET    /api_contacts/index.php/users                 (admin)
//  GET    /api_contacts/index.php/users?q=term          (admin)
//  GET    /api_contacts/index.php/users?id=1            (admin)
//  PUT    /api_contacts/index.php/users?id=1            (admin: disable / password)
//
//  Fallback: ?resource=contacts|users|login|register|ping
// ============================================================

require_once __DIR__ . '/config/db.php';
require_once __DIR__ . '/config/helpers.php';

setCORSHeaders();

$method   = $_SERVER['REQUEST_METHOD'];
$resource = getResource();
$db       = getDB();

if ($method === 'GET' && ($resource === 'ping' || isset($_GET['ping']))) {
    respond(200, ['status' => 'OK', 'timestamp' => time()]);
}

if ($resource === 'register' && $method === 'POST') {
    handleRegister($db);
}

if ($resource === 'login' && $method === 'POST') {
    handleLogin($db);
}

if ($resource === 'contacts') {
    $user = requireAuth();
    switch ($method) {
        case 'GET':
            handleGetContacts($db, $user);
            break;
        case 'POST':
            handleCreateContact($db, $user);
            break;
        case 'PUT':
            handleUpdateContact($db, $user);
            break;
        case 'DELETE':
            handleDeleteContact($db, $user);
            break;
        default:
            respond(405, ['error' => 'Method not allowed']);
    }
}

if ($resource === 'users') {
    $admin = requireAdmin();
    switch ($method) {
        case 'GET':
            handleGetUsers($db);
            break;
        case 'PUT':
            handleUpdateUser($db, $admin);
            break;
        default:
            respond(405, ['error' => 'Method not allowed']);
    }
}

respond(404, ['error' => 'Unknown resource']);

// ── Register / Login ─────────────────────────────────────────

function handleRegister($db) {
    $body      = getRequestBody();
    $firstName = clean($body['firstName'] ?? $body['FirstName'] ?? '');
    $lastName  = clean($body['lastName'] ?? $body['LastName'] ?? '');
    $login     = clean($body['login'] ?? '');
    $password  = $body['password'] ?? '';

    if (!$firstName || !$lastName || !$login || $password === '') {
        respond(400, ['error' => 'firstName, lastName, login, and password are required']);
    }

    $check = $db->prepare('SELECT ID FROM Users WHERE Login = :login LIMIT 1');
    $check->execute([':login' => $login]);
    if ($check->fetch()) {
        respond(409, ['error' => 'Login already exists']);
    }

    $stmt = $db->prepare(
        'INSERT INTO Users (FirstName, LastName, Login, Password, IsAdmin, Disabled)
         VALUES (:first, :last, :login, :pass, 0, 0)'
    );
    $stmt->execute([
        ':first' => $firstName,
        ':last'  => $lastName,
        ':login' => $login,
        ':pass'  => hashPassword($password),
    ]);

    $id = (int) $db->lastInsertId();
    respond(201, [
        'message'   => 'User created',
        'id'        => $id,
        'firstName' => $firstName,
        'lastName'  => $lastName,
        'login'     => $login,
        'isAdmin'   => false,
        'token'     => (string) $id,
        'error'     => '',
    ]);
}

function handleLogin($db) {
    $body     = getRequestBody();
    $login    = clean($body['login'] ?? '');
    $password = $body['password'] ?? '';

    if (!$login || $password === '') {
        respond(400, ['error' => 'Login and password are required']);
    }

    $stmt = $db->prepare(
        'SELECT ID, FirstName, LastName, Login, Password, IsAdmin, Disabled
         FROM Users WHERE Login = :login LIMIT 1'
    );
    $stmt->execute([':login' => $login]);
    $user = $stmt->fetch();

    if (!$user || !verifyPassword($password, $user['Password'])) {
        respond(401, [
            'id'        => 0,
            'firstName' => '',
            'lastName'  => '',
            'error'     => 'No Records Found',
        ]);
    }

    if ((int) $user['Disabled'] === 1) {
        respond(401, ['error' => 'Account disabled']);
    }

    respond(200, [
        'id'        => (int) $user['ID'],
        'firstName' => $user['FirstName'],
        'lastName'  => $user['LastName'],
        'login'     => $user['Login'],
        'isAdmin'   => (int) $user['IsAdmin'] === 1,
        'token'     => (string) $user['ID'],
        'error'     => '',
    ]);
}

// ── Contacts ─────────────────────────────────────────────────

function contactSelectSql() {
    return 'SELECT ID, UserID, FirstName, LastName, Email, Phone FROM Contacts';
}

function handleGetContacts($db, $user) {
    $id       = isset($_GET['id']) ? (int) $_GET['id'] : null;
    $search   = isset($_GET['q']) ? trim($_GET['q']) : (isset($_GET['search']) ? trim($_GET['search']) : null);
    $isAdmin  = (int) $user['IsAdmin'] === 1;
    $filterUid = isset($_GET['userId']) ? (int) $_GET['userId'] : null;

    if ($id) {
        $sql = contactSelectSql() . ' WHERE ID = :id';
        $params = [':id' => $id];
        if (!$isAdmin) {
            $sql .= ' AND UserID = :uid';
            $params[':uid'] = (int) $user['ID'];
        }
        $sql .= ' LIMIT 1';
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        $row = $stmt->fetch();
        if (!$row) {
            respond(404, ['error' => 'Contact not found']);
        }
        respond(200, formatContact($row));
    }

    $sql = contactSelectSql() . ' WHERE 1=1';
    $params = [];

    if ($isAdmin) {
        if ($filterUid) {
            $sql .= ' AND UserID = :uid';
            $params[':uid'] = $filterUid;
        }
    } else {
        $sql .= ' AND UserID = :uid';
        $params[':uid'] = (int) $user['ID'];
    }

    if ($search !== null && $search !== '') {
        $sql .= ' AND (FirstName LIKE :q OR LastName LIKE :q OR Email LIKE :q OR Phone LIKE :q)';
        $params[':q'] = '%' . $search . '%';
    }

    $sql .= ' ORDER BY LastName, FirstName';
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();
    $contacts = array_map('formatContact', $rows);

    if (empty($contacts)) {
        respond(200, ['contacts' => [], 'error' => 'No Records Found']);
    }
    respond(200, ['contacts' => $contacts, 'error' => '']);
}

function parseContactFields($body, $requireName) {
    $fields = [
        'firstName' => clean($body['firstName'] ?? $body['FirstName'] ?? ''),
        'lastName'  => clean($body['lastName'] ?? $body['LastName'] ?? ''),
        'email'     => clean($body['email'] ?? $body['Email'] ?? ''),
        'phone'     => clean($body['phone'] ?? $body['Phone'] ?? ''),
    ];

    if ($requireName && ($fields['firstName'] === '' || $fields['lastName'] === '')) {
        respond(400, ['error' => 'firstName and lastName are required']);
    }

    return $fields;
}

function handleCreateContact($db, $user) {
    $fields = parseContactFields(getRequestBody(), true);

    $stmt = $db->prepare(
        'INSERT INTO Contacts (UserID, FirstName, LastName, Email, Phone)
         VALUES (:uid, :first, :last, :email, :phone)'
    );
    $stmt->execute([
        ':uid'   => (int) $user['ID'],
        ':first' => $fields['firstName'],
        ':last'  => $fields['lastName'],
        ':email' => $fields['email'],
        ':phone' => $fields['phone'],
    ]);

    $id = (int) $db->lastInsertId();
    respond(201, [
        'message'   => 'Contact created',
        'id'        => $id,
        'userId'    => (int) $user['ID'],
        'firstName' => $fields['firstName'],
        'lastName'  => $fields['lastName'],
        'email'     => $fields['email'],
        'phone'     => $fields['phone'],
        'error'     => '',
    ]);
}

function handleUpdateContact($db, $user) {
    $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
    if (!$id) {
        respond(400, ['error' => 'Contact ID is required — use ?id=']);
    }

    $isAdmin = (int) $user['IsAdmin'] === 1;
    $sql = contactSelectSql() . ' WHERE ID = :id';
    $params = [':id' => $id];
    if (!$isAdmin) {
        $sql .= ' AND UserID = :uid';
        $params[':uid'] = (int) $user['ID'];
    }
    $sql .= ' LIMIT 1';
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $existing = $stmt->fetch();
    if (!$existing) {
        respond(404, ['error' => 'Contact not found']);
    }

    $body = getRequestBody();
    unset($body['id'], $body['ID'], $body['userId'], $body['UserID'], $body['user_id']);

    $firstName = array_key_exists('firstName', $body) || array_key_exists('FirstName', $body)
        ? clean($body['firstName'] ?? $body['FirstName'] ?? '')
        : $existing['FirstName'];
    $lastName = array_key_exists('lastName', $body) || array_key_exists('LastName', $body)
        ? clean($body['lastName'] ?? $body['LastName'] ?? '')
        : $existing['LastName'];
    $email = array_key_exists('email', $body) || array_key_exists('Email', $body)
        ? clean($body['email'] ?? $body['Email'] ?? '')
        : $existing['Email'];
    $phone = array_key_exists('phone', $body) || array_key_exists('Phone', $body)
        ? clean($body['phone'] ?? $body['Phone'] ?? '')
        : $existing['Phone'];

    if ($firstName === '' || $lastName === '') {
        respond(400, ['error' => 'firstName and lastName are required']);
    }

    $update = $db->prepare(
        'UPDATE Contacts SET FirstName = :first, LastName = :last, Email = :email, Phone = :phone
         WHERE ID = :id'
    );
    $update->execute([
        ':first' => $firstName,
        ':last'  => $lastName,
        ':email' => $email,
        ':phone' => $phone,
        ':id'    => $id,
    ]);

    respond(200, [
        'message'   => 'Contact updated',
        'id'        => $id,
        'userId'    => (int) $existing['UserID'],
        'firstName' => $firstName,
        'lastName'  => $lastName,
        'email'     => $email,
        'phone'     => $phone,
        'error'     => '',
    ]);
}

function handleDeleteContact($db, $user) {
    $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
    if (!$id) {
        respond(400, ['error' => 'Contact ID is required — use ?id=']);
    }

    $isAdmin = (int) $user['IsAdmin'] === 1;
    if ($isAdmin) {
        $stmt = $db->prepare('DELETE FROM Contacts WHERE ID = :id');
        $stmt->execute([':id' => $id]);
    } else {
        $stmt = $db->prepare('DELETE FROM Contacts WHERE ID = :id AND UserID = :uid');
        $stmt->execute([':id' => $id, ':uid' => (int) $user['ID']]);
    }

    if ($stmt->rowCount() === 0) {
        respond(404, ['error' => 'Contact not found']);
    }

    respond(200, ['message' => 'Contact deleted', 'error' => '']);
}

// ── Admin users ──────────────────────────────────────────────

function fetchContactsForUser($db, $userId) {
    $stmt = $db->prepare(contactSelectSql() . ' WHERE UserID = :uid ORDER BY LastName, FirstName');
    $stmt->execute([':uid' => $userId]);
    return array_map('formatContact', $stmt->fetchAll());
}

function handleGetUsers($db) {
    $id     = isset($_GET['id']) ? (int) $_GET['id'] : null;
    $search = isset($_GET['q']) ? trim($_GET['q']) : (isset($_GET['search']) ? trim($_GET['search']) : null);

    if ($id) {
        $stmt = $db->prepare(
            'SELECT ID, FirstName, LastName, Login, IsAdmin, Disabled FROM Users WHERE ID = :id LIMIT 1'
        );
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        if (!$row) {
            respond(404, ['error' => 'User not found']);
        }
        $payload = formatUser($row);
        $payload['contacts'] = fetchContactsForUser($db, $id);
        respond(200, $payload);
    }

    $sql = 'SELECT ID, FirstName, LastName, Login, IsAdmin, Disabled FROM Users WHERE 1=1';
    $params = [];
    if ($search !== null && $search !== '') {
        $sql .= ' AND (FirstName LIKE :q OR LastName LIKE :q OR Login LIKE :q)';
        $params[':q'] = '%' . $search . '%';
    }
    $sql .= ' ORDER BY LastName, FirstName';
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    $users = [];
    foreach ($rows as $row) {
        $item = formatUser($row);
        $item['contacts'] = fetchContactsForUser($db, (int) $row['ID']);
        $users[] = $item;
    }

    if (empty($users)) {
        respond(200, ['users' => [], 'error' => 'No Records Found']);
    }
    respond(200, ['users' => $users, 'error' => '']);
}

function handleUpdateUser($db, $admin) {
    $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
    if (!$id) {
        respond(400, ['error' => 'User ID is required — use ?id=']);
    }

    $stmt = $db->prepare(
        'SELECT ID, FirstName, LastName, Login, IsAdmin, Disabled FROM Users WHERE ID = :id LIMIT 1'
    );
    $stmt->execute([':id' => $id]);
    $existing = $stmt->fetch();
    if (!$existing) {
        respond(404, ['error' => 'User not found']);
    }

    $body = getRequestBody();
    $updates = [];
    $params = [':id' => $id];

    $hasDisabled = array_key_exists('disabled', $body) || array_key_exists('Disabled', $body);
    $hasPassword = array_key_exists('password', $body) || array_key_exists('Password', $body);

    if (!$hasDisabled && !$hasPassword) {
        respond(400, ['error' => 'Provide disabled and/or password']);
    }

    if ($hasDisabled) {
        $raw = $body['disabled'] ?? $body['Disabled'];
        $disabled = filter_var($raw, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        if ($disabled === null && ($raw === 0 || $raw === '0' || $raw === 1 || $raw === '1')) {
            $disabled = (int) $raw === 1;
        }
        if ($disabled === null) {
            respond(400, ['error' => 'disabled must be true or false']);
        }
        $updates[] = 'Disabled = :disabled';
        $params[':disabled'] = $disabled ? 1 : 0;
    }

    if ($hasPassword) {
        $password = $body['password'] ?? $body['Password'] ?? '';
        if ($password === '') {
            respond(400, ['error' => 'password cannot be empty']);
        }
        $updates[] = 'Password = :pass';
        $params[':pass'] = hashPassword($password);
    }

    $sql = 'UPDATE Users SET ' . implode(', ', $updates) . ' WHERE ID = :id';
    $db->prepare($sql)->execute($params);

    $stmt->execute([':id' => $id]);
    $updated = $stmt->fetch();
    $payload = formatUser($updated);
    $payload['message'] = 'User updated';
    $payload['error'] = '';
    respond(200, $payload);
}
