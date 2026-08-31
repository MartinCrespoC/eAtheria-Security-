import { describe, it, expect } from "vitest";
import { cn, formatBytes, formatCurrency, slugify, getSeverityColor, generateRandomString } from "@/lib/utils";

describe("cn", () => {
  it("merges class names", () => {
    expect(cn("foo", "bar")).toBe("foo bar");
  });

  it("handles conditional classes", () => {
    expect(cn("base", false && "hidden", "visible")).toBe("base visible");
  });

  it("merges tailwind classes correctly", () => {
    expect(cn("p-4", "p-2")).toBe("p-2");
    expect(cn("text-red-500", "text-blue-500")).toBe("text-blue-500");
  });
});

describe("formatBytes", () => {
  it("formats zero", () => {
    expect(formatBytes(0)).toBe("0 Bytes");
  });

  it("formats bytes", () => {
    expect(formatBytes(500)).toBe("500 Bytes");
  });

  it("formats KB", () => {
    expect(formatBytes(1024)).toBe("1 KB");
  });

  it("formats MB", () => {
    expect(formatBytes(1048576)).toBe("1 MB");
  });

  it("formats GB", () => {
    expect(formatBytes(1073741824)).toBe("1 GB");
  });

  it("respects decimals", () => {
    expect(formatBytes(1536, 1)).toBe("1.5 KB");
  });
});

describe("formatCurrency", () => {
  it("formats USD", () => {
    expect(formatCurrency(99.99)).toBe("$99.99");
  });

  it("formats large amounts", () => {
    expect(formatCurrency(1234.5)).toBe("$1,234.50");
  });
});

describe("slugify", () => {
  it("converts to lowercase slug", () => {
    expect(slugify("Hello World")).toBe("hello-world");
  });

  it("removes special characters", () => {
    expect(slugify("Hello! @World#")).toBe("hello-world");
  });

  it("handles multiple spaces", () => {
    expect(slugify("hello   world")).toBe("hello-world");
  });

  it("trims whitespace", () => {
    expect(slugify("  hello  ")).toBe("hello");
  });
});

describe("getSeverityColor", () => {
  it("returns critical color", () => {
    expect(getSeverityColor("CRITICAL")).toContain("text-red-500");
  });

  it("returns high color", () => {
    expect(getSeverityColor("HIGH")).toContain("text-orange-500");
  });

  it("returns medium color", () => {
    expect(getSeverityColor("MEDIUM")).toContain("text-yellow-500");
  });

  it("returns low color", () => {
    expect(getSeverityColor("LOW")).toContain("text-blue-500");
  });

  it("returns default for unknown", () => {
    expect(getSeverityColor("UNKNOWN")).toContain("text-gray-500");
  });
});

describe("generateRandomString", () => {
  it("generates correct length", () => {
    expect(generateRandomString(16)).toHaveLength(16);
    expect(generateRandomString(64)).toHaveLength(64);
  });

  it("defaults to 32", () => {
    expect(generateRandomString()).toHaveLength(32);
  });

  it("generates unique strings", () => {
    const a = generateRandomString();
    const b = generateRandomString();
    expect(a).not.toBe(b);
  });
});
