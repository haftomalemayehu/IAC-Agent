package com.iacagent.iacagent.runner;

import java.util.ArrayList;
import java.util.List;

/**
 * A genuine, structure-aware tokenizer for the subset of HCL native syntax
 * {@link TerraformNativeSourceExtractor} needs: identifiers, quoted string literals (with escape
 * and {@code ${...}} interpolation awareness), heredoc strings, line/block comments, and the
 * bracket/brace/paren/equals punctuation needed to track real nesting structure. This is NOT a
 * line-based or regex-based scan - a string, heredoc, or comment that happens to contain
 * {@code {}}/{@code #}/newline-like text is handled correctly because this lexer consumes those
 * constructs as atomic units before ever looking for structural punctuation, exactly as a real HCL
 * lexer must.
 *
 * <p>Deliberately does NOT implement the rest of the HCL expression grammar (numbers with full
 * exponent syntax, all operators, template directives inside strings other than {@code ${...}}
 * detection). Everything this lexer does not specifically recognize as IDENT/STRING/bracket
 * punctuation becomes an {@link HclToken.Type#OTHER} token - {@link TerraformNativeSourceExtractor}
 * only ever bases an accepted extraction on an immediate {@code STRING} token for a {@code source}
 * attribute, so an {@code OTHER} token appearing where a source value was expected correctly causes
 * that extractor to fail closed rather than to guess.
 */
final class HclLexer {

    private final String source;
    private int pos;
    private final int length;

    private HclLexer(String source) {
        this.source = source;
        this.length = source.length();
    }

    static List<HclToken> tokenize(String source) {
        return new HclLexer(source).run();
    }

    private List<HclToken> run() {
        List<HclToken> tokens = new ArrayList<>();
        while (true) {
            skipWhitespaceAndComments();
            if (pos >= length) {
                tokens.add(HclToken.of(HclToken.Type.EOF));
                return tokens;
            }
            char c = source.charAt(pos);
            if (c == '\n') {
                pos++;
                tokens.add(HclToken.of(HclToken.Type.NEWLINE));
            } else if (c == '{') {
                pos++;
                tokens.add(HclToken.of(HclToken.Type.LBRACE));
            } else if (c == '}') {
                pos++;
                tokens.add(HclToken.of(HclToken.Type.RBRACE));
            } else if (c == '[') {
                pos++;
                tokens.add(HclToken.of(HclToken.Type.LBRACKET));
            } else if (c == ']') {
                pos++;
                tokens.add(HclToken.of(HclToken.Type.RBRACKET));
            } else if (c == '(') {
                pos++;
                tokens.add(HclToken.of(HclToken.Type.LPAREN));
            } else if (c == ')') {
                pos++;
                tokens.add(HclToken.of(HclToken.Type.RPAREN));
            } else if (c == '=' && peek(1) != '=') {
                pos++;
                tokens.add(HclToken.of(HclToken.Type.EQUALS));
            } else if (c == '.' && !Character.isDigit(peek(1))) {
                // A bare '.' (attribute/reference access, e.g. "corpaws.east") - deliberately
                // distinguished from a '.' inside a numeric literal (e.g. "1.5"), which this lexer
                // otherwise treats as an opaque OTHER token since numeric values are never a
                // provider reference and are consumed generically as part of a scalar expression.
                pos++;
                tokens.add(HclToken.of(HclToken.Type.DOT));
            } else if (c == '"') {
                tokens.add(readQuotedString());
            } else if (c == '<' && peek(1) == '<') {
                tokens.add(readHeredoc());
            } else if (isIdentStart(c)) {
                tokens.add(readIdent());
            } else {
                pos++;
                tokens.add(HclToken.of(HclToken.Type.OTHER));
            }
        }
    }

    private char peek(int offset) {
        int p = pos + offset;
        return p < length ? source.charAt(p) : '\0';
    }

    private void skipWhitespaceAndComments() {
        while (pos < length) {
            char c = source.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\r') {
                pos++;
            } else if (c == '#' || (c == '/' && peek(1) == '/')) {
                while (pos < length && source.charAt(pos) != '\n') {
                    pos++;
                }
            } else if (c == '/' && peek(1) == '*') {
                pos += 2;
                while (pos < length && !(source.charAt(pos) == '*' && peek(1) == '/')) {
                    pos++;
                }
                pos = Math.min(pos + 2, length);
            } else {
                return;
            }
        }
    }

    private static boolean isIdentStart(char c) {
        return Character.isLetter(c) || c == '_';
    }

    private static boolean isIdentPart(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '-';
    }

    private HclToken readIdent() {
        int start = pos;
        while (pos < length && isIdentPart(source.charAt(pos))) {
            pos++;
        }
        return HclToken.ident(source.substring(start, pos));
    }

    /** Reads a {@code "..."} string, honoring {@code \"}/{@code \\} escapes so an escaped quote
     * never terminates the string early - the exact defense a naive regex/line scan lacks. Flags
     * {@code hasInterpolation} if the raw (post-escape-decode) content contains {@code ${}. */
    private HclToken readQuotedString() {
        pos++; // opening quote
        StringBuilder value = new StringBuilder();
        boolean interpolation = false;
        while (pos < length) {
            char c = source.charAt(pos);
            if (c == '"') {
                pos++;
                return HclToken.string(value.toString(), interpolation);
            }
            if (c == '\\' && pos + 1 < length) {
                char next = source.charAt(pos + 1);
                value.append(switch (next) {
                    case 'n' -> '\n';
                    case 't' -> '\t';
                    case 'r' -> '\r';
                    default -> next; // covers \" \\ and anything else - decoded literally
                });
                pos += 2;
                continue;
            }
            if (c == '$' && peek(1) == '{') {
                interpolation = true;
            }
            value.append(c);
            pos++;
        }
        // unterminated string - the caller (TerraformNativeSourceExtractor) treats a malformed
        // token stream as an extraction failure, never as "no string found here."
        return HclToken.string(value.toString(), true);
    }

    /** Reads a {@code <<MARKER ... MARKER} or {@code <<-MARKER ... MARKER} heredoc as one atomic
     * STRING token (never treated as a plain literal - see {@link #hasInterpolation}). This exists
     * so a heredoc body's own {@code {}/}}/quote characters are never misread as structural
     * punctuation elsewhere in the token stream. */
    private HclToken readHeredoc() {
        pos += 2; // <<
        boolean indented = false;
        if (pos < length && source.charAt(pos) == '-') {
            indented = true;
            pos++;
        }
        int markerStart = pos;
        while (pos < length && isIdentPart(source.charAt(pos))) {
            pos++;
        }
        String marker = source.substring(markerStart, pos);
        while (pos < length && source.charAt(pos) != '\n') {
            pos++; // rest of the opening line
        }
        if (pos < length) {
            pos++; // consume the newline
        }
        StringBuilder body = new StringBuilder();
        while (pos < length) {
            int lineStart = pos;
            while (pos < length && source.charAt(pos) != '\n') {
                pos++;
            }
            String line = source.substring(lineStart, pos);
            String trimmed = indented ? line.strip() : line;
            if (trimmed.equals(marker)) {
                if (pos < length) {
                    pos++; // consume trailing newline after the marker line
                }
                return HclToken.string(body.toString(), true); // heredocs are never a plain literal
            }
            body.append(line).append('\n');
            if (pos < length) {
                pos++;
            }
        }
        return HclToken.string(body.toString(), true); // unterminated heredoc - treated as unsafe, not plain
    }
}
