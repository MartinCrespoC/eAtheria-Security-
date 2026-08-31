/**
 * False Positive Patterns for C#
 */

export const CSHARP_FALSE_POSITIVES = [
  {
    language: "csharp",
    pattern: "Console\\.Write",
    description: "Console output for debugging",
    reason: "Console.WriteLine is commonly used for debugging in development",
    context: "development",
    cweIds: ["CWE-532"],
    examples: [
      'Console.WriteLine($"Debug: {data}");',
      'Console.Write("Processing...");',
    ],
  },
  {
    language: "csharp",
    pattern: "Debug\\.Write",
    description: "Debug class output",
    reason: "Debug output is removed in Release builds",
    context: "development",
    cweIds: ["CWE-489"],
    examples: [
      'Debug.WriteLine("Checkpoint reached");',
      'Debug.Assert(user != null);',
    ],
  },
  {
    language: "csharp",
    pattern: "\\[Obsolete\\]",
    description: "Obsolete attribute",
    reason: "Marks deprecated code, not a vulnerability",
    context: "deprecation",
    cweIds: ["CWE-1164"],
    examples: [
      '[Obsolete("Use NewMethod instead")]',
      '[Obsolete("This method will be removed in v2.0", true)]',
    ],
  },
  {
    language: "csharp",
    pattern: "SqlCommand.*Parameters\\.Add",
    description: "Parameterized SQL queries",
    reason: "Using parameters prevents SQL injection",
    context: "safe-sql",
    cweIds: ["CWE-89"],
    examples: [
      'cmd.Parameters.AddWithValue("@userId", userId);',
      'cmd.Parameters.Add("@name", SqlDbType.NVarChar).Value = name;',
    ],
  },
  {
    language: "csharp",
    pattern: "\\?\\?|\\?\\.",
    description: "Null-coalescing and null-conditional operators",
    reason: "C# null-safety operators",
    context: "null-safety",
    cweIds: ["CWE-476"],
    examples: [
      'var name = user?.Name ?? "Unknown";',
      'return value ?? defaultValue;',
    ],
  },
  {
    language: "csharp",
    pattern: "\\[Authorize\\]",
    description: "ASP.NET authorization attribute",
    reason: "Standard ASP.NET Core authorization",
    context: "framework",
    cweIds: ["CWE-862"],
    examples: [
      '[Authorize(Roles = "Admin")]',
      '[Authorize(Policy = "RequireAdminRole")]',
    ],
  },
  {
    language: "csharp",
    pattern: "ILogger\\.",
    description: "Microsoft.Extensions.Logging",
    reason: "Standard .NET logging framework",
    context: "logging",
    cweIds: ["CWE-532"],
    examples: [
      '_logger.LogInformation("User {UserId} logged in", userId);',
      'logger.LogDebug("Processing request");',
    ],
  },
  {
    language: "csharp",
    pattern: "async\\s+Task",
    description: "Async/await pattern",
    reason: "Standard C# asynchronous programming",
    context: "async",
    cweIds: ["CWE-362"],
    examples: [
      'public async Task<User> GetUserAsync(int id)',
      'await userService.CreateAsync(user);',
    ],
  },
  {
    language: "csharp",
    pattern: "\\[TestMethod\\]|\\[Fact\\]",
    description: "Unit test attributes",
    reason: "MSTest or xUnit test markers",
    context: "testing",
    cweIds: ["CWE-489"],
    examples: [
      '[TestMethod] public void TestUserCreation()',
      '[Fact] public void Should_Create_User()',
    ],
  },
  {
    language: "csharp",
    pattern: "nameof\\(",
    description: "nameof operator",
    reason: "Type-safe way to get member names",
    context: "reflection",
    cweIds: ["CWE-915"],
    examples: [
      'throw new ArgumentNullException(nameof(user));',
      'PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Name)));',
    ],
  },
];
