/**
 * False Positive Patterns for Ruby
 */

export const RUBY_FALSE_POSITIVES = [
  {
    language: "ruby",
    pattern: "puts|p\\s+",
    description: "Print statements for debugging",
    reason: "puts and p are commonly used for debugging",
    context: "development",
    cweIds: ["CWE-532"],
    examples: [
      'puts "Debug: #{data}"',
      'p user',
    ],
  },
  {
    language: "ruby",
    pattern: "ActiveRecord.*where\\(",
    description: "ActiveRecord parameterized queries",
    reason: "ActiveRecord automatically parameterizes queries",
    context: "safe-sql",
    cweIds: ["CWE-89"],
    examples: [
      'User.where("email = ?", email)',
      'Post.where(user_id: user_id)',
    ],
  },
  {
    language: "ruby",
    pattern: "html_safe",
    description: "html_safe when content is sanitized",
    reason: "Safe when used with sanitized content",
    context: "sanitized",
    cweIds: ["CWE-79"],
    examples: [
      'sanitize(user_input).html_safe',
      'content_tag(:div, sanitized_content).html_safe',
    ],
  },
  {
    language: "ruby",
    pattern: "ENV\\[",
    description: "Environment variables",
    reason: "Environment variables are administrator-controlled",
    context: "configuration",
    cweIds: ["CWE-526"],
    examples: [
      'api_key = ENV["API_KEY"]',
      'db_url = ENV.fetch("DATABASE_URL")',
    ],
  },
  {
    language: "ruby",
    pattern: "__FILE__|__dir__",
    description: "File path constants",
    reason: "Built-in constants for file paths",
    context: "file-system",
    cweIds: ["CWE-22"],
    examples: [
      'require_relative File.join(__dir__, "config")',
      'path = File.dirname(__FILE__)',
    ],
  },
  {
    language: "ruby",
    pattern: "attr_accessor|attr_reader",
    description: "Attribute accessors",
    reason: "Standard Ruby metaprogramming for getters/setters",
    context: "metaprogramming",
    cweIds: ["CWE-915"],
    examples: [
      'attr_accessor :name, :email',
      'attr_reader :id',
    ],
  },
  {
    language: "ruby",
    pattern: "Rails\\.logger",
    description: "Rails logging",
    reason: "Standard Rails logging framework",
    context: "logging",
    cweIds: ["CWE-532"],
    examples: [
      'Rails.logger.info "User logged in: #{user.id}"',
      'Rails.logger.debug "Processing request"',
    ],
  },
  {
    language: "ruby",
    pattern: "rescue\\s+",
    description: "Exception handling",
    reason: "Standard Ruby exception handling",
    context: "error-handling",
    cweIds: ["CWE-755"],
    examples: [
      'begin; risky_operation; rescue => e; handle_error(e); end',
      'def method; rescue StandardError => e; end',
    ],
  },
  {
    language: "ruby",
    pattern: "describe|it\\s+",
    description: "RSpec test blocks",
    reason: "RSpec testing framework",
    context: "testing",
    cweIds: ["CWE-489"],
    examples: [
      'describe User do',
      'it "creates a user" do',
    ],
  },
];
