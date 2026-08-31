/**
 * False Positive Patterns for PHP
 */

export const PHP_FALSE_POSITIVES = [
  {
    language: "php",
    pattern: "var_dump|print_r",
    description: "Debug output functions",
    reason: "Used for debugging in development, typically removed in production",
    context: "development",
    cweIds: ["CWE-532"],
    examples: [
      'var_dump($data);',
      'print_r($array, true);',
    ],
  },
  {
    language: "php",
    pattern: "PDO::prepare",
    description: "PDO prepared statements",
    reason: "Prepared statements prevent SQL injection",
    context: "safe-sql",
    cweIds: ["CWE-89"],
    examples: [
      '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");',
      '$stmt->execute([$userId]);',
    ],
  },
  {
    language: "php",
    pattern: "htmlspecialchars|htmlentities",
    description: "HTML encoding functions",
    reason: "Properly encoding output prevents XSS",
    context: "xss-prevention",
    cweIds: ["CWE-79"],
    examples: [
      'echo htmlspecialchars($userInput, ENT_QUOTES, "UTF-8");',
      '$safe = htmlentities($data);',
    ],
  },
  {
    language: "php",
    pattern: "password_hash|password_verify",
    description: "Password hashing functions",
    reason: "Standard PHP password hashing (bcrypt)",
    context: "cryptography",
    cweIds: ["CWE-916"],
    examples: [
      '$hash = password_hash($password, PASSWORD_BCRYPT);',
      'if (password_verify($input, $hash)) {}',
    ],
  },
  {
    language: "php",
    pattern: "filter_var.*FILTER_",
    description: "Input filtering",
    reason: "PHP filter functions for input validation",
    context: "validation",
    cweIds: ["CWE-20"],
    examples: [
      'filter_var($email, FILTER_VALIDATE_EMAIL);',
      'filter_var($url, FILTER_SANITIZE_URL);',
    ],
  },
  {
    language: "php",
    pattern: "__DIR__|__FILE__",
    description: "Magic constants",
    reason: "PHP magic constants for file paths, not user input",
    context: "file-system",
    cweIds: ["CWE-22"],
    examples: [
      'require_once __DIR__ . "/config.php";',
      '$path = dirname(__FILE__);',
    ],
  },
  {
    language: "php",
    pattern: "session_start|\\$_SESSION",
    description: "Session management",
    reason: "Standard PHP session handling",
    context: "session",
    cweIds: ["CWE-384"],
    examples: [
      'session_start();',
      '$_SESSION["user_id"] = $userId;',
    ],
  },
  {
    language: "php",
    pattern: "json_encode|json_decode",
    description: "JSON encoding/decoding",
    reason: "Standard JSON handling",
    context: "serialization",
    cweIds: ["CWE-502"],
    examples: [
      '$json = json_encode($data);',
      '$obj = json_decode($json, true);',
    ],
  },
  {
    language: "php",
    pattern: "isset|empty",
    description: "Variable checking",
    reason: "Standard PHP variable existence checks",
    context: "validation",
    cweIds: ["CWE-476"],
    examples: [
      'if (isset($_POST["username"])) {}',
      'if (!empty($data)) {}',
    ],
  },
  {
    language: "php",
    pattern: "namespace\\s+",
    description: "Namespace declarations",
    reason: "PHP namespaces for code organization",
    context: "language-feature",
    cweIds: ["CWE-1164"],
    examples: [
      'namespace App\\Controllers;',
      'use App\\Models\\User;',
    ],
  },
];
