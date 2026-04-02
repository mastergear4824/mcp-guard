import { describe, it, expect } from "vitest";
import { normalizeHomoglyphs, containsHomoglyphs } from "../../detectors/homoglyph.js";

describe("normalizeHomoglyphs", () => {
  it("converts Cyrillic а to Latin a", () => {
    expect(normalizeHomoglyphs("\u0430")).toBe("a");
  });

  it("converts Cyrillic е to Latin e", () => {
    expect(normalizeHomoglyphs("\u0435")).toBe("e");
  });

  it("converts Cyrillic о to Latin o", () => {
    expect(normalizeHomoglyphs("\u043E")).toBe("o");
  });

  it("converts Cyrillic с to Latin c", () => {
    expect(normalizeHomoglyphs("\u0441")).toBe("c");
  });

  it("converts Cyrillic р to Latin p", () => {
    expect(normalizeHomoglyphs("\u0440")).toBe("p");
  });

  it("leaves pure ASCII text unchanged", () => {
    expect(normalizeHomoglyphs("read_file")).toBe("read_file");
  });

  it("normalizes mixed Cyrillic/Latin text", () => {
    // r + Cyrillic е + Cyrillic а + d_fil + Cyrillic е
    const mixed = "r\u0435\u0430d_fil\u0435";
    expect(normalizeHomoglyphs(mixed)).toBe("read_file");
  });
});

describe("containsHomoglyphs", () => {
  it("detects mixed Cyrillic in 'rеаd_filе'", () => {
    // Cyrillic е (\u0435) and а (\u0430) mixed with ASCII
    const input = "r\u0435\u0430d_fil\u0435";
    const result = containsHomoglyphs(input);
    expect(result.found).toBe(true);
    expect(result.count).toBe(3);
    expect(result.normalized).toBe("read_file");
  });

  it("returns found: false for pure ASCII text", () => {
    const result = containsHomoglyphs("read_file");
    expect(result.found).toBe(false);
    expect(result.count).toBe(0);
    expect(result.normalized).toBe("read_file");
  });

  it("counts correct number of homoglyphs", () => {
    // 5 Cyrillic characters: а, е, о, с, р
    const input = "\u0430\u0435\u043E\u0441\u0440";
    const result = containsHomoglyphs(input);
    expect(result.found).toBe(true);
    expect(result.count).toBe(5);
    expect(result.normalized).toBe("aeocp");
  });

  it("detects Greek homoglyphs", () => {
    // Greek α (\u03B1) and ο (\u03BF)
    const input = "\u03B1bc\u03BFd";
    const result = containsHomoglyphs(input);
    expect(result.found).toBe(true);
    expect(result.count).toBe(2);
  });
});
