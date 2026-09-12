package com.iacagent.iacagent.runner;

/**
 * One lexical token produced by {@link HclLexer}. {@code text} is the decoded value for
 * {@link Type#STRING} (quotes/escapes removed, heredoc markers stripped) and the raw source text
 * for {@link Type#IDENT}; it is unused (empty) for punctuation types. {@code hasInterpolation} is
 * meaningful only for {@link Type#STRING}: {@code true} means the literal contains a {@code ${...}}
 * interpolation sequence (or was a heredoc, which this parser never treats as a plain literal) and
 * therefore is NOT a value {@link TerraformNativeSourceExtractor} will ever accept as a {@code
 * source} attribute's value - see that class for why.
 */
record HclToken(Type type, String text, boolean hasInterpolation) {

    enum Type {
        IDENT, STRING, LBRACE, RBRACE, LBRACKET, RBRACKET, LPAREN, RPAREN, EQUALS, DOT, NEWLINE, OTHER, EOF
    }

    static HclToken of(Type type) {
        return new HclToken(type, "", false);
    }

    static HclToken ident(String text) {
        return new HclToken(Type.IDENT, text, false);
    }

    static HclToken string(String text, boolean hasInterpolation) {
        return new HclToken(Type.STRING, text, hasInterpolation);
    }
}
