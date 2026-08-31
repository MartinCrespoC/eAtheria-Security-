/**
 * False Positive Patterns for Java
 */

export const JAVA_FALSE_POSITIVES = [
  {
    language: "java",
    pattern: "System\\.out\\.print",
    description: "System.out for debugging",
    reason: "Console output is commonly used for debugging and is removed in production builds",
    context: "development",
    cweIds: ["CWE-532"],
    examples: [
      'System.out.println("Debug: " + data);',
      'System.out.printf("Value: %d%n", value);',
    ],
  },
  {
    language: "java",
    pattern: "@SuppressWarnings",
    description: "SuppressWarnings annotation",
    reason: "Used to suppress known false positives from static analysis tools",
    context: "code-quality",
    cweIds: ["CWE-1164"],
    examples: [
      '@SuppressWarnings("unchecked")',
      '@SuppressWarnings({"rawtypes", "unchecked"})',
    ],
  },
  {
    language: "java",
    pattern: "PreparedStatement\\.set",
    description: "PreparedStatement with parameterized queries",
    reason: "PreparedStatement prevents SQL injection when used correctly",
    context: "safe-sql",
    cweIds: ["CWE-89"],
    examples: [
      'stmt.setString(1, userInput);',
      'stmt.setInt(2, userId);',
    ],
  },
  {
    language: "java",
    pattern: "prepareStatement\\(\\s*\"(?:[^\"\\\\]|\\\\.)*\"\\s*\\)",
    description: "prepareStatement with a fixed literal SQL string (parameterized query)",
    reason: "The SQL text is a compile-time constant and values are bound via placeholders — no user input is concatenated into the query",
    context: "safe-sql",
    cweIds: ["CWE-89"],
    examples: [
      'sqlStatement.setString(1, data);',
      'preparedStatement.setInt(1, id);',
    ],
  },
  {
    language: "java",
    pattern: "=\\s*\"foo\"\\s*;",
    description: "Hardcoded benign test value (not user-controlled data)",
    reason: "The sensitive variable is assigned a fixed benign literal — no attacker input flows into the sink",
    context: "hardcoded-source",
    cweIds: ["CWE-23", "CWE-78", "CWE-80", "CWE-601"],
    examples: [
      'String data = "foo";',
    ],
  },
  {
    language: "java",
    pattern: "readLine\\(\\)[\\s\\S]*?getConnection\\(",
    description: "Credential read from console input before use (not hardcoded)",
    reason: "The password comes from interactive input (readLine) rather than a hardcoded literal — the CWE-259 finding requires a secret constant in source",
    context: "input-credential",
    cweIds: ["CWE-259"],
    examples: [
      'data = readerBuffered.readLine();\nconnection = DriverManager.getConnection(url, "root", data);',
    ],
  },
  {
    language: "java",
    pattern: "Cipher\\.getInstance\\(\"AES",
    description: "AES cipher usage (strong algorithm)",
    reason: "AES with a proper key size is a strong cipher — the weak-algorithm finding applies to DES/RC4/ECB-era algorithms",
    context: "strong-crypto",
    cweIds: ["CWE-327"],
    examples: [
      'Cipher aesCipher = Cipher.getInstance("AES");',
    ],
  },
  {
    language: "java",
    pattern: "Objects\\.requireNonNull",
    description: "Null checking with Objects.requireNonNull",
    reason: "Standard Java null-safety pattern",
    context: "validation",
    cweIds: ["CWE-476"],
    examples: [
      'Objects.requireNonNull(user, "User cannot be null");',
      'this.name = Objects.requireNonNull(name);',
    ],
  },
  {
    language: "java",
    pattern: "@Autowired|@Inject",
    description: "Dependency injection annotations",
    reason: "Standard Spring/Jakarta EE dependency injection",
    context: "framework",
    cweIds: ["CWE-915"],
    examples: [
      '@Autowired private UserService userService;',
      '@Inject private DataSource dataSource;',
    ],
  },
  {
    language: "java",
    pattern: "Logger\\.(debug|info|trace)",
    description: "Logging framework usage",
    reason: "Standard logging with SLF4J, Log4j, or java.util.logging",
    context: "logging",
    cweIds: ["CWE-532"],
    examples: [
      'logger.debug("Processing request: {}", request);',
      'log.info("User logged in: {}", username);',
    ],
  },
  {
    language: "java",
    pattern: "Optional\\.",
    description: "Optional API usage",
    reason: "Java 8+ Optional for null-safety",
    context: "null-safety",
    cweIds: ["CWE-476"],
    examples: [
      'Optional<User> user = userRepository.findById(id);',
      'return Optional.ofNullable(value);',
    ],
  },
  {
    language: "java",
    pattern: "Stream\\.",
    description: "Java Streams API",
    reason: "Standard Java 8+ functional programming",
    context: "standard-library",
    cweIds: ["CWE-1164"],
    examples: [
      'list.stream().filter(x -> x > 0).collect(Collectors.toList());',
      'users.stream().map(User::getName).forEach(System.out::println);',
    ],
  },
  {
    language: "java",
    pattern: "@Test",
    description: "JUnit test annotations",
    reason: "Standard testing framework annotations",
    context: "testing",
    cweIds: ["CWE-489"],
    examples: [
      '@Test public void testUserCreation() {}',
      '@Test(expected = IllegalArgumentException.class)',
    ],
  },
];
