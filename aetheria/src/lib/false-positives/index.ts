/**
 * False Positive Patterns Index
 * Aggregates all language-specific patterns
 */

import { JAVASCRIPT_FALSE_POSITIVES } from "./patterns-javascript";
import { PYTHON_FALSE_POSITIVES } from "./patterns-python";
import { JAVA_FALSE_POSITIVES } from "./patterns-java";
import { CSHARP_FALSE_POSITIVES } from "./patterns-csharp";
import { PHP_FALSE_POSITIVES } from "./patterns-php";
import { RUBY_FALSE_POSITIVES } from "./patterns-ruby";
import { GO_FALSE_POSITIVES } from "./patterns-go";
import { RUST_FALSE_POSITIVES } from "./patterns-rust";
import { KOTLIN_FALSE_POSITIVES } from "./patterns-kotlin";
import { SWIFT_FALSE_POSITIVES } from "./patterns-swift";
import { SCALA_FALSE_POSITIVES } from "./patterns-scala";
import { SAP_FALSE_POSITIVES } from "./patterns-sap";

export const ALL_FALSE_POSITIVE_PATTERNS = [
  ...JAVASCRIPT_FALSE_POSITIVES,
  ...PYTHON_FALSE_POSITIVES,
  ...JAVA_FALSE_POSITIVES,
  ...CSHARP_FALSE_POSITIVES,
  ...PHP_FALSE_POSITIVES,
  ...RUBY_FALSE_POSITIVES,
  ...GO_FALSE_POSITIVES,
  ...RUST_FALSE_POSITIVES,
  ...KOTLIN_FALSE_POSITIVES,
  ...SWIFT_FALSE_POSITIVES,
  ...SCALA_FALSE_POSITIVES,
  ...SAP_FALSE_POSITIVES,
];

export const SUPPORTED_LANGUAGES = [
  "javascript",
  "typescript",
  "python",
  "java",
  "csharp",
  "php",
  "ruby",
  "go",
  "rust",
  "c",
  "cpp",
  "kotlin",
  "swift",
  "scala",
  "abap",
  "sap",
];

export {
  JAVASCRIPT_FALSE_POSITIVES,
  PYTHON_FALSE_POSITIVES,
  KOTLIN_FALSE_POSITIVES,
  SWIFT_FALSE_POSITIVES,
  SCALA_FALSE_POSITIVES,
  JAVA_FALSE_POSITIVES,
  CSHARP_FALSE_POSITIVES,
  PHP_FALSE_POSITIVES,
  RUBY_FALSE_POSITIVES,
  GO_FALSE_POSITIVES,
  RUST_FALSE_POSITIVES,
  SAP_FALSE_POSITIVES,
};
