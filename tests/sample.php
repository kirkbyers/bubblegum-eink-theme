<?php
/**
 * PHP Sample File for Theme Testing
 * This file demonstrates various PHP syntax and features for comprehensive theme testing
 */

declare(strict_types=1);

namespace App\UserManagement;

use DateTime;
use DateTimeImmutable;
use Exception;
use InvalidArgumentException;
use JsonSerializable;
use PDO;
use PDOException;

/**
 * User entity class with validation and serialization
 */
class User implements JsonSerializable
{
    // Class constants
    public const ROLE_ADMIN = 'admin';
    public const ROLE_USER = 'user';
    public const ROLE_GUEST = 'guest';
    
    public const STATUS_ACTIVE = 'active';
    public const STATUS_INACTIVE = 'inactive';
    public const STATUS_PENDING = 'pending';

    // Properties with type declarations
    private int $id;
    private string $name;
    private string $email;
    private string $role;
    private string $status;
    private DateTimeImmutable $createdAt;
    private ?array $preferences;
    private ?string $passwordHash;

    /**
     * Constructor with parameter validation
     */
    public function __construct(
        int $id,
        string $name,
        string $email,
        string $role = self::ROLE_USER,
        string $status = self::STATUS_PENDING,
        ?DateTimeImmutable $createdAt = null,
        ?array $preferences = null
    ) {
        $this->setId($id);
        $this->setName($name);
        $this->setEmail($email);
        $this->setRole($role);
        $this->setStatus($status);
        $this->createdAt = $createdAt ?? new DateTimeImmutable();
        $this->preferences = $preferences ?? [];
    }

    // Getter methods
    public function getId(): int
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function getRole(): string
    {
        return $this->role;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function getCreatedAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getPreferences(): ?array
    {
        return $this->preferences;
    }

    // Setter methods with validation
    public function setId(int $id): void
    {
        if ($id <= 0) {
            throw new InvalidArgumentException('User ID must be positive');
        }
        $this->id = $id;
    }

    public function setName(string $name): void
    {
        $trimmedName = trim($name);
        if (empty($trimmedName)) {
            throw new InvalidArgumentException('Name cannot be empty');
        }
        if (strlen($trimmedName) > 255) {
            throw new InvalidArgumentException('Name cannot exceed 255 characters');
        }
        $this->name = $trimmedName;
    }

    public function setEmail(string $email): void
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new InvalidArgumentException('Invalid email format');
        }
        $this->email = strtolower(trim($email));
    }

    public function setRole(string $role): void
    {
        $validRoles = [self::ROLE_ADMIN, self::ROLE_USER, self::ROLE_GUEST];
        if (!in_array($role, $validRoles)) {
            throw new InvalidArgumentException('Invalid role: ' . $role);
        }
        $this->role = $role;
    }

    public function setStatus(string $status): void
    {
        $validStatuses = [self::STATUS_ACTIVE, self::STATUS_INACTIVE, self::STATUS_PENDING];
        if (!in_array($status, $validStatuses)) {
            throw new InvalidArgumentException('Invalid status: ' . $status);
        }
        $this->status = $status;
    }

    public function setPreferences(?array $preferences): void
    {
        $this->preferences = $preferences;
    }

    public function setPasswordHash(string $password): void
    {
        $this->passwordHash = password_hash($password, PASSWORD_ARGON2ID);
    }

    public function verifyPassword(string $password): bool
    {
        return $this->passwordHash && password_verify($password, $this->passwordHash);
    }

    // Utility methods
    public function isActive(): bool
    {
        return $this->status === self::STATUS_ACTIVE;
    }

    public function isAdmin(): bool
    {
        return $this->role === self::ROLE_ADMIN;
    }

    public function getDisplayName(): string
    {
        return $this->name ?: explode('@', $this->email)[0];
    }

    public function getDaysSinceCreation(): int
    {
        $now = new DateTimeImmutable();
        return $now->diff($this->createdAt)->days;
    }

    // JsonSerializable implementation
    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'role' => $this->role,
            'status' => $this->status,
            'created_at' => $this->createdAt->format('c'),
            'preferences' => $this->preferences,
            'display_name' => $this->getDisplayName(),
            'is_active' => $this->isActive(),
            'is_admin' => $this->isAdmin(),
            'days_since_creation' => $this->getDaysSinceCreation()
        ];
    }

    // Magic methods
    public function __toString(): string
    {
        return "{$this->name} <{$this->email}> ({$this->role})";
    }

    public function __clone()
    {
        $this->id = 0; // Reset ID for cloned objects
        $this->createdAt = new DateTimeImmutable();
    }
}

/**
 * Custom exception for user management operations
 */
class UserException extends Exception
{
    public const ERROR_NOT_FOUND = 1001;
    public const ERROR_DUPLICATE_EMAIL = 1002;
    public const ERROR_INVALID_CREDENTIALS = 1003;
    public const ERROR_PERMISSION_DENIED = 1004;

    private ?int $userId;

    public function __construct(
        string $message = '',
        int $code = 0,
        ?Exception $previous = null,
        ?int $userId = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->userId = $userId;
    }

    public function getUserId(): ?int
    {
        return $this->userId;
    }
}

/**
 * Interface for user storage backends
 */
interface UserRepositoryInterface
{
    public function find(int $id): ?User;
    public function findByEmail(string $email): ?User;
    public function findAll(array $filters = []): array;
    public function save(User $user): bool;
    public function delete(int $id): bool;
    public function count(array $filters = []): int;
}

/**
 * Database implementation of user repository
 */
class DatabaseUserRepository implements UserRepositoryInterface
{
    private PDO $connection;
    private string $tableName;

    public function __construct(PDO $connection, string $tableName = 'users')
    {
        $this->connection = $connection;
        $this->tableName = $tableName;
    }

    public function find(int $id): ?User
    {
        $sql = "SELECT * FROM {$this->tableName} WHERE id = :id";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue(':id', $id, PDO::PARAM_INT);
        $stmt->execute();

        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $this->createUserFromRow($row) : null;
    }

    public function findByEmail(string $email): ?User
    {
        $sql = "SELECT * FROM {$this->tableName} WHERE email = :email";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue(':email', $email);
        $stmt->execute();

        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $this->createUserFromRow($row) : null;
    }

    public function findAll(array $filters = []): array
    {
        $sql = "SELECT * FROM {$this->tableName}";
        $conditions = [];
        $parameters = [];

        // Dynamic query building based on filters
        if (!empty($filters['role'])) {
            $conditions[] = 'role = :role';
            $parameters[':role'] = $filters['role'];
        }

        if (!empty($filters['status'])) {
            $conditions[] = 'status = :status';
            $parameters[':status'] = $filters['status'];
        }

        if (!empty($filters['search'])) {
            $conditions[] = '(name LIKE :search OR email LIKE :search)';
            $parameters[':search'] = '%' . $filters['search'] . '%';
        }

        if ($conditions) {
            $sql .= ' WHERE ' . implode(' AND ', $conditions);
        }

        // Ordering and pagination
        $sql .= ' ORDER BY created_at DESC';

        if (!empty($filters['limit'])) {
            $sql .= ' LIMIT :limit';
            $parameters[':limit'] = (int) $filters['limit'];
        }

        if (!empty($filters['offset'])) {
            $sql .= ' OFFSET :offset';
            $parameters[':offset'] = (int) $filters['offset'];
        }

        $stmt = $this->connection->prepare($sql);

        // Bind parameters with appropriate types
        foreach ($parameters as $key => $value) {
            $type = is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR;
            $stmt->bindValue($key, $value, $type);
        }

        $stmt->execute();

        $users = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $users[] = $this->createUserFromRow($row);
        }

        return $users;
    }

    public function save(User $user): bool
    {
        try {
            if ($user->getId() > 0 && $this->find($user->getId())) {
                return $this->updateUser($user);
            } else {
                return $this->insertUser($user);
            }
        } catch (PDOException $e) {
            if ($e->getCode() === '23000') { // Integrity constraint violation
                throw new UserException(
                    'Email already exists',
                    UserException::ERROR_DUPLICATE_EMAIL,
                    $e
                );
            }
            throw $e;
        }
    }

    public function delete(int $id): bool
    {
        $sql = "DELETE FROM {$this->tableName} WHERE id = :id";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue(':id', $id, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->rowCount() > 0;
    }

    public function count(array $filters = []): int
    {
        $sql = "SELECT COUNT(*) FROM {$this->tableName}";
        $conditions = [];
        $parameters = [];

        // Apply same filters as findAll
        if (!empty($filters['role'])) {
            $conditions[] = 'role = :role';
            $parameters[':role'] = $filters['role'];
        }

        if (!empty($filters['status'])) {
            $conditions[] = 'status = :status';
            $parameters[':status'] = $filters['status'];
        }

        if ($conditions) {
            $sql .= ' WHERE ' . implode(' AND ', $conditions);
        }

        $stmt = $this->connection->prepare($sql);
        foreach ($parameters as $key => $value) {
            $stmt->bindValue($key, $value);
        }
        $stmt->execute();

        return (int) $stmt->fetchColumn();
    }

    private function insertUser(User $user): bool
    {
        $sql = "INSERT INTO {$this->tableName} 
                (name, email, role, status, created_at, preferences) 
                VALUES (:name, :email, :role, :status, :created_at, :preferences)";

        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue(':name', $user->getName());
        $stmt->bindValue(':email', $user->getEmail());
        $stmt->bindValue(':role', $user->getRole());
        $stmt->bindValue(':status', $user->getStatus());
        $stmt->bindValue(':created_at', $user->getCreatedAt()->format('Y-m-d H:i:s'));
        $stmt->bindValue(':preferences', json_encode($user->getPreferences()));

        return $stmt->execute();
    }

    private function updateUser(User $user): bool
    {
        $sql = "UPDATE {$this->tableName} 
                SET name = :name, email = :email, role = :role, 
                    status = :status, preferences = :preferences 
                WHERE id = :id";

        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue(':id', $user->getId(), PDO::PARAM_INT);
        $stmt->bindValue(':name', $user->getName());
        $stmt->bindValue(':email', $user->getEmail());
        $stmt->bindValue(':role', $user->getRole());
        $stmt->bindValue(':status', $user->getStatus());
        $stmt->bindValue(':preferences', json_encode($user->getPreferences()));

        return $stmt->execute();
    }

    private function createUserFromRow(array $row): User
    {
        $user = new User(
            (int) $row['id'],
            $row['name'],
            $row['email'],
            $row['role'],
            $row['status'],
            new DateTimeImmutable($row['created_at']),
            json_decode($row['preferences'] ?? '{}', true)
        );

        return $user;
    }
}

/**
 * Service class for user management business logic
 */
class UserService
{
    private UserRepositoryInterface $repository;
    private array $config;

    public function __construct(UserRepositoryInterface $repository, array $config = [])
    {
        $this->repository = $repository;
        $this->config = array_merge([
            'max_users' => 10000,
            'require_email_verification' => true,
            'default_role' => User::ROLE_USER,
            'password_min_length' => 8
        ], $config);
    }

    /**
     * Create a new user with validation
     */
    public function createUser(array $userData, ?string $password = null): User
    {
        // Check if email already exists
        if ($this->repository->findByEmail($userData['email'])) {
            throw new UserException(
                'Email already exists',
                UserException::ERROR_DUPLICATE_EMAIL
            );
        }

        // Check user limit
        if ($this->repository->count() >= $this->config['max_users']) {
            throw new UserException('Maximum number of users reached');
        }

        // Validate password if provided
        if ($password && strlen($password) < $this->config['password_min_length']) {
            throw new InvalidArgumentException(
                "Password must be at least {$this->config['password_min_length']} characters long"
            );
        }

        // Create user object
        $user = new User(
            0, // Will be set by database
            $userData['name'],
            $userData['email'],
            $userData['role'] ?? $this->config['default_role'],
            $this->config['require_email_verification'] ? User::STATUS_PENDING : User::STATUS_ACTIVE,
            null,
            $userData['preferences'] ?? []
        );

        if ($password) {
            $user->setPasswordHash($password);
        }

        if (!$this->repository->save($user)) {
            throw new UserException('Failed to create user');
        }

        return $user;
    }

    /**
     * Authenticate user with email and password
     */
    public function authenticate(string $email, string $password): User
    {
        $user = $this->repository->findByEmail($email);

        if (!$user) {
            throw new UserException(
                'Invalid credentials',
                UserException::ERROR_INVALID_CREDENTIALS
            );
        }

        if (!$user->verifyPassword($password)) {
            throw new UserException(
                'Invalid credentials',
                UserException::ERROR_INVALID_CREDENTIALS,
                null,
                $user->getId()
            );
        }

        if (!$user->isActive()) {
            throw new UserException(
                'Account is not active',
                UserException::ERROR_PERMISSION_DENIED,
                null,
                $user->getId()
            );
        }

        return $user;
    }

    /**
     * Get paginated list of users with filters
     */
    public function getUsers(array $filters = [], int $page = 1, int $perPage = 20): array
    {
        $offset = ($page - 1) * $perPage;
        $filters['limit'] = $perPage;
        $filters['offset'] = $offset;

        $users = $this->repository->findAll($filters);
        $total = $this->repository->count($filters);

        return [
            'users' => $users,
            'pagination' => [
                'current_page' => $page,
                'per_page' => $perPage,
                'total' => $total,
                'last_page' => ceil($total / $perPage)
            ]
        ];
    }

    /**
     * Update user information
     */
    public function updateUser(int $id, array $updates): User
    {
        $user = $this->repository->find($id);

        if (!$user) {
            throw new UserException(
                'User not found',
                UserException::ERROR_NOT_FOUND,
                null,
                $id
            );
        }

        // Apply updates
        foreach ($updates as $field => $value) {
            switch ($field) {
                case 'name':
                    $user->setName($value);
                    break;
                case 'email':
                    // Check if new email is unique
                    $existingUser = $this->repository->findByEmail($value);
                    if ($existingUser && $existingUser->getId() !== $id) {
                        throw new UserException(
                            'Email already exists',
                            UserException::ERROR_DUPLICATE_EMAIL
                        );
                    }
                    $user->setEmail($value);
                    break;
                case 'role':
                    $user->setRole($value);
                    break;
                case 'status':
                    $user->setStatus($value);
                    break;
                case 'preferences':
                    $user->setPreferences($value);
                    break;
            }
        }

        if (!$this->repository->save($user)) {
            throw new UserException('Failed to update user');
        }

        return $user;
    }

    /**
     * Delete user by ID
     */
    public function deleteUser(int $id): bool
    {
        $user = $this->repository->find($id);

        if (!$user) {
            throw new UserException(
                'User not found',
                UserException::ERROR_NOT_FOUND,
                null,
                $id
            );
        }

        return $this->repository->delete($id);
    }

    /**
     * Generate user statistics
     */
    public function getUserStatistics(): array
    {
        $total = $this->repository->count();
        $active = $this->repository->count(['status' => User::STATUS_ACTIVE]);
        $inactive = $this->repository->count(['status' => User::STATUS_INACTIVE]);
        $pending = $this->repository->count(['status' => User::STATUS_PENDING]);

        $admins = $this->repository->count(['role' => User::ROLE_ADMIN]);
        $users = $this->repository->count(['role' => User::ROLE_USER]);
        $guests = $this->repository->count(['role' => User::ROLE_GUEST]);

        return [
            'total_users' => $total,
            'by_status' => [
                'active' => $active,
                'inactive' => $inactive,
                'pending' => $pending
            ],
            'by_role' => [
                'admin' => $admins,
                'user' => $users,
                'guest' => $guests
            ],
            'activity_rate' => $total > 0 ? round(($active / $total) * 100, 2) : 0
        ];
    }
}

/**
 * Utility class for various helper functions
 */
class UserUtils
{
    /**
     * Generate a secure random password
     */
    public static function generatePassword(int $length = 12): string
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        $password = '';

        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, strlen($chars) - 1)];
        }

        return $password;
    }

    /**
     * Validate password strength
     */
    public static function validatePasswordStrength(string $password): array
    {
        $errors = [];

        if (strlen($password) < 8) {
            $errors[] = 'Password must be at least 8 characters long';
        }

        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter';
        }

        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter';
        }

        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one number';
        }

        if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one special character';
        }

        return [
            'is_valid' => empty($errors),
            'errors' => $errors,
            'strength' => self::calculatePasswordStrength($password)
        ];
    }

    private static function calculatePasswordStrength(string $password): string
    {
        $score = 0;

        // Length bonus
        $score += min(strlen($password) * 2, 50);

        // Character variety bonus
        if (preg_match('/[a-z]/', $password)) $score += 10;
        if (preg_match('/[A-Z]/', $password)) $score += 10;
        if (preg_match('/[0-9]/', $password)) $score += 10;
        if (preg_match('/[^a-zA-Z0-9]/', $password)) $score += 15;

        // Deduct points for common patterns
        if (preg_match('/(.)\1{2,}/', $password)) $score -= 10; // Repeated characters
        if (preg_match('/123|abc|qwe/i', $password)) $score -= 15; // Sequential characters

        if ($score >= 80) return 'strong';
        if ($score >= 60) return 'medium';
        if ($score >= 40) return 'weak';
        return 'very_weak';
    }

    /**
     * Export users to CSV format
     */
    public static function exportToCsv(array $users): string
    {
        $csv = "ID,Name,Email,Role,Status,Created At\n";

        foreach ($users as $user) {
            $csv .= sprintf(
                "%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                $user->getId(),
                str_replace('"', '""', $user->getName()),
                $user->getEmail(),
                $user->getRole(),
                $user->getStatus(),
                $user->getCreatedAt()->format('Y-m-d H:i:s')
            );
        }

        return $csv;
    }

    /**
     * Send email notification (mock implementation)
     */
    public static function sendNotification(User $user, string $subject, string $message): bool
    {
        // In a real application, this would use a mail library like PHPMailer or SwiftMailer
        error_log("Email notification sent to {$user->getEmail()}: {$subject}");
        return true;
    }
}

// Example usage and demonstration
try {
    // Create database connection (example)
    $pdo = new PDO('sqlite::memory:');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Create users table
    $pdo->exec('
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            role VARCHAR(50) NOT NULL,
            status VARCHAR(50) NOT NULL,
            created_at DATETIME NOT NULL,
            preferences TEXT
        )
    ');

    // Initialize services
    $repository = new DatabaseUserRepository($pdo);
    $userService = new UserService($repository);

    // Create some sample users
    $users = [
        ['name' => 'John Doe', 'email' => 'john@example.com', 'role' => User::ROLE_ADMIN],
        ['name' => 'Jane Smith', 'email' => 'jane@example.com', 'role' => User::ROLE_USER],
        ['name' => 'Bob Johnson', 'email' => 'bob@example.com', 'role' => User::ROLE_USER]
    ];

    foreach ($users as $userData) {
        $user = $userService->createUser($userData, UserUtils::generatePassword());
        echo "Created user: {$user}\n";
    }

    // Demonstrate various operations
    $stats = $userService->getUserStatistics();
    echo "User statistics: " . json_encode($stats, JSON_PRETTY_PRINT) . "\n";

    $userList = $userService->getUsers(['role' => User::ROLE_USER]);
    echo "Found {$userList['pagination']['total']} users\n";

    // Export to CSV
    $csvData = UserUtils::exportToCsv($userList['users']);
    echo "CSV export completed\n";

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    if ($e instanceof UserException) {
        echo "Error code: " . $e->getCode() . "\n";
        if ($e->getUserId()) {
            echo "User ID: " . $e->getUserId() . "\n";
        }
    }
}

// Anonymous functions and closures
$userFilter = function(User $user) use ($userService): bool {
    return $user->isActive() && $user->getDaysSinceCreation() > 30;
};

$userTransformer = fn(User $user): array => [
    'id' => $user->getId(),
    'display_name' => $user->getDisplayName(),
    'is_admin' => $user->isAdmin()
];

// Array functions and operations
$sampleUsers = $repository->findAll();
$activeUsers = array_filter($sampleUsers, fn($user) => $user->isActive());
$userNames = array_map(fn($user) => $user->getName(), $activeUsers);
$adminUsers = array_filter($sampleUsers, fn($user) => $user->isAdmin());

echo "Active users: " . implode(', ', $userNames) . "\n";
echo "Admin count: " . count($adminUsers) . "\n";

?>

<!-- HTML template example -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Management</title>
</head>
<body>
    <h1>User Management System</h1>
    
    <?php if (!empty($sampleUsers)): ?>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($sampleUsers as $user): ?>
                    <tr>
                        <td><?= htmlspecialchars($user->getId()) ?></td>
                        <td><?= htmlspecialchars($user->getName()) ?></td>
                        <td><?= htmlspecialchars($user->getEmail()) ?></td>
                        <td><?= htmlspecialchars(ucfirst($user->getRole())) ?></td>
                        <td class="status-<?= $user->getStatus() ?>">
                            <?= htmlspecialchars(ucfirst($user->getStatus())) ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else: ?>
        <p>No users found.</p>
    <?php endif; ?>

    <script>
        // JavaScript within PHP
        console.log('Total users: <?= count($sampleUsers) ?>');
    </script>
</body>
</html>