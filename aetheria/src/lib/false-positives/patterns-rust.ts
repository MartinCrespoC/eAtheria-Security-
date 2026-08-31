/**
 * False Positive Patterns for Rust
 */

export const RUST_FALSE_POSITIVES = [
  {
    language: "rust",
    pattern: "println!|dbg!",
    description: "Print macros for debugging",
    reason: "println! and dbg! are commonly used for debugging",
    context: "development",
    cweIds: ["CWE-532"],
    examples: [
      'println!("Debug: {:?}", data);',
      'dbg!(user);',
    ],
  },
  {
    language: "rust",
    pattern: "unwrap\\(\\)",
    description: "unwrap() in controlled contexts",
    reason: "unwrap() is acceptable when panic is intended or in tests",
    context: "controlled-panic",
    cweIds: ["CWE-754"],
    examples: [
      'let value = option.unwrap(); // Known to be Some',
      'config.get("key").unwrap() // Config guaranteed to have key',
    ],
  },
  {
    language: "rust",
    pattern: "expect\\(",
    description: "expect() with descriptive messages",
    reason: "expect() provides better error messages than unwrap()",
    context: "error-handling",
    cweIds: ["CWE-754"],
    examples: [
      'file.expect("Failed to open config file");',
      'value.expect("Value must be present at this point");',
    ],
  },
  {
    language: "rust",
    pattern: "unsafe\\s*\\{",
    description: "Unsafe blocks with justification",
    reason: "Unsafe is necessary for FFI, performance, or low-level operations",
    context: "ffi-performance",
    cweIds: ["CWE-119"],
    examples: [
      'unsafe { libc::malloc(size) }',
      'unsafe { std::ptr::write(ptr, value) }',
    ],
  },
  {
    language: "rust",
    pattern: "env::var",
    description: "Environment variables",
    reason: "Environment variables are administrator-controlled",
    context: "configuration",
    cweIds: ["CWE-526"],
    examples: [
      'let api_key = env::var("API_KEY")?;',
      'env::var("DATABASE_URL").unwrap_or_default()',
    ],
  },
  {
    language: "rust",
    pattern: "#\\[derive\\(",
    description: "Derive macros",
    reason: "Standard Rust trait derivation",
    context: "macros",
    cweIds: ["CWE-1164"],
    examples: [
      '#[derive(Debug, Clone)]',
      '#[derive(Serialize, Deserialize)]',
    ],
  },
  {
    language: "rust",
    pattern: "match\\s+",
    description: "Pattern matching",
    reason: "Rust's exhaustive pattern matching ensures safety",
    context: "pattern-matching",
    cweIds: ["CWE-478"],
    examples: [
      'match result { Ok(v) => v, Err(e) => handle(e) }',
      'match option { Some(x) => x, None => default }',
    ],
  },
  {
    language: "rust",
    pattern: "#\\[test\\]",
    description: "Test attribute",
    reason: "Rust testing framework",
    context: "testing",
    cweIds: ["CWE-489"],
    examples: [
      '#[test] fn test_user_creation() {}',
      '#[cfg(test)] mod tests {}',
    ],
  },
  {
    language: "rust",
    pattern: "Arc<|Rc<",
    description: "Reference counting",
    reason: "Standard Rust memory management patterns",
    context: "memory-management",
    cweIds: ["CWE-404"],
    examples: [
      'let shared = Arc::new(data);',
      'let rc = Rc::new(value);',
    ],
  },
];
