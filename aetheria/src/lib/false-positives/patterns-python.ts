/**
 * False Positive Patterns for Python
 * Common development patterns that are not actual vulnerabilities
 */

export const PYTHON_FALSE_POSITIVES = [
  {
    language: "python",
    pattern: "print\\(",
    description: "Print statements for debugging",
    reason: "Print statements are commonly used for debugging and logging in development",
    context: "development",
    cweIds: ["CWE-532"],
    examples: [
      'print("Debug:", data)',
      'print(f"Processing {item}")',
      'if DEBUG: print("Checkpoint reached")',
    ],
  },
  {
    language: "python",
    pattern: "eval\\(.*\\)",
    description: "eval() with controlled input",
    reason: "When used with ast.literal_eval or with developer-controlled expressions, eval is safe",
    context: "controlled",
    cweIds: ["CWE-94"],
    examples: [
      'result = ast.literal_eval(safe_string)',
      'value = eval("2 + 2")  # Static expression',
    ],
  },
  {
    language: "python",
    pattern: "exec\\(.*\\)",
    description: "exec() in controlled environment",
    reason: "exec() with trusted code in sandboxed environments or for code generation is acceptable",
    context: "trusted",
    cweIds: ["CWE-94"],
    examples: [
      'exec(compile(trusted_code, "<string>", "exec"))',
    ],
  },
  {
    language: "python",
    pattern: "pickle\\.loads?\\(",
    description: "Pickle with trusted data",
    reason: "Pickle is safe when deserializing data from trusted sources (own application, signed data)",
    context: "trusted",
    cweIds: ["CWE-502"],
    examples: [
      'data = pickle.load(open("cache.pkl", "rb"))  # Own cache file',
      'obj = pickle.loads(signed_data)  # Cryptographically signed',
    ],
  },
  {
    language: "python",
    pattern: "os\\.environ\\[",
    description: "Environment variables",
    reason: "Environment variables are administrator-controlled configuration, not user input",
    context: "configuration",
    cweIds: ["CWE-526"],
    examples: [
      'api_key = os.environ["API_KEY"]',
      'db_url = os.environ.get("DATABASE_URL", "default")',
    ],
  },
  {
    language: "python",
    pattern: "__file__|__name__",
    description: "Python module constants",
    reason: "Built-in module constants that provide metadata, not user input",
    context: "module-system",
    cweIds: ["CWE-22"],
    examples: [
      'config_path = os.path.join(os.path.dirname(__file__), "config.yaml")',
      'if __name__ == "__main__":',
    ],
  },
  {
    language: "python",
    pattern: "assert\\s+",
    description: "Assert statements",
    reason: "Assertions are for development/testing and are removed with -O flag in production",
    context: "development",
    cweIds: ["CWE-617"],
    examples: [
      'assert user is not None, "User must be authenticated"',
      'assert len(data) > 0',
    ],
  },
  {
    language: "python",
    pattern: "\\.format\\(",
    description: "String formatting",
    reason: "str.format() is safe when not used with user-controlled format strings",
    context: "developer-controlled",
    cweIds: ["CWE-134"],
    examples: [
      'message = "Hello, {}".format(name)',
      'query = "SELECT * FROM {} WHERE id = %s".format(table_name)',
    ],
  },
  {
    language: "python",
    pattern: "f['\"].*\\{.*\\}",
    description: "F-strings",
    reason: "F-strings are safe for formatting, the vulnerability is in what you do with the result",
    context: "formatting",
    cweIds: ["CWE-134"],
    examples: [
      'log_msg = f"User {user.id} logged in"',
      'path = f"/api/users/{user_id}"',
    ],
  },
  {
    language: "python",
    pattern: "open\\(.*['\"]r['\"]",
    description: "Opening files in read mode",
    reason: "Reading files is generally safe, especially config files in known locations",
    context: "read-only",
    cweIds: ["CWE-73"],
    examples: [
      'with open("config.json", "r") as f:',
      'data = open("/etc/app/settings.conf", "r").read()',
    ],
  },
  {
    language: "python",
    pattern: "\\*\\*kwargs",
    description: "Keyword arguments unpacking",
    reason: "**kwargs is a standard Python pattern for flexible function signatures",
    context: "function-signature",
    cweIds: ["CWE-915"],
    examples: [
      'def process(**kwargs):',
      'result = function(**config)',
    ],
  },
  {
    language: "python",
    pattern: "getattr\\(.*\\)",
    description: "getattr with controlled attribute names",
    reason: "getattr is safe when attribute names come from developer-controlled sources",
    context: "controlled",
    cweIds: ["CWE-915"],
    examples: [
      'value = getattr(obj, "safe_attribute", default)',
      'method = getattr(self, f"handle_{action}")  # Controlled actions',
    ],
  },
  {
    language: "python",
    pattern: "subprocess\\.run\\(\\[",
    description: "subprocess with list arguments",
    reason: "Using list form of subprocess prevents shell injection",
    context: "safe-subprocess",
    cweIds: ["CWE-78"],
    examples: [
      'subprocess.run(["ls", "-la", directory])',
      'subprocess.run(["/usr/bin/convert", input_file, output_file])',
    ],
  },
  {
    language: "python",
    pattern: "\\@property",
    description: "Property decorators",
    reason: "Property decorators are standard Python for computed attributes",
    context: "language-feature",
    cweIds: ["CWE-915"],
    examples: [
      '@property\ndef full_name(self):',
      '@cached_property\ndef expensive_calculation(self):',
    ],
  },
];
