/**
 * False Positive Patterns for Go
 */

export const GO_FALSE_POSITIVES = [
  {
    language: "go",
    pattern: "fmt\\.Print",
    description: "fmt package for output",
    reason: "fmt.Println is commonly used for debugging",
    context: "development",
    cweIds: ["CWE-532"],
    examples: [
      'fmt.Println("Debug:", data)',
      'fmt.Printf("Value: %v\\n", value)',
    ],
  },
  {
    language: "go",
    pattern: "log\\.",
    description: "Standard log package",
    reason: "Go standard library logging",
    context: "logging",
    cweIds: ["CWE-532"],
    examples: [
      'log.Println("Processing request")',
      'log.Printf("User %s logged in", username)',
    ],
  },
  {
    language: "go",
    pattern: "sql\\.DB.*Query.*\\$",
    description: "Parameterized SQL queries",
    reason: "Using $1, $2 placeholders prevents SQL injection",
    context: "safe-sql",
    cweIds: ["CWE-89"],
    examples: [
      'db.Query("SELECT * FROM users WHERE id = $1", userId)',
      'stmt.Exec($1, $2)',
    ],
  },
  {
    language: "go",
    pattern: "if err != nil",
    description: "Error checking",
    reason: "Standard Go error handling pattern",
    context: "error-handling",
    cweIds: ["CWE-755"],
    examples: [
      'if err != nil { return err }',
      'if err := doSomething(); err != nil {}',
    ],
  },
  {
    language: "go",
    pattern: "defer\\s+",
    description: "Defer statements",
    reason: "Standard Go resource cleanup pattern",
    context: "resource-management",
    cweIds: ["CWE-404"],
    examples: [
      'defer file.Close()',
      'defer mu.Unlock()',
    ],
  },
  {
    language: "go",
    pattern: "context\\.",
    description: "Context package usage",
    reason: "Standard Go context for cancellation and timeouts",
    context: "concurrency",
    cweIds: ["CWE-362"],
    examples: [
      'ctx := context.Background()',
      'ctx, cancel := context.WithTimeout(parent, time.Second)',
    ],
  },
  {
    language: "go",
    pattern: "os\\.Getenv",
    description: "Environment variables",
    reason: "Environment variables are administrator-controlled",
    context: "configuration",
    cweIds: ["CWE-526"],
    examples: [
      'apiKey := os.Getenv("API_KEY")',
      'port := os.Getenv("PORT")',
    ],
  },
  {
    language: "go",
    pattern: "go\\s+func",
    description: "Goroutines",
    reason: "Standard Go concurrency pattern",
    context: "concurrency",
    cweIds: ["CWE-362"],
    examples: [
      'go func() { process(data) }()',
      'go worker(jobs, results)',
    ],
  },
  {
    language: "go",
    pattern: "t\\.Test|t\\.Run",
    description: "Testing functions",
    reason: "Go testing framework",
    context: "testing",
    cweIds: ["CWE-489"],
    examples: [
      'func TestUserCreation(t *testing.T) {}',
      't.Run("creates user", func(t *testing.T) {})',
    ],
  },
];
