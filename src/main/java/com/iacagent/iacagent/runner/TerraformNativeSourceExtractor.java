package com.iacagent.iacagent.runner;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A real, structure-aware parser for the subset of HCL native syntax ({@code *.tf}) needed to
 * deterministically extract {@code terraform.required_providers[*].source} and {@code
 * module.*.source} declarations - replacing the Phase 2B-4 line/regex-based
 * {@code TerraformConfigSourceScanner}, which review correctly rejected as unable to serve as an
 * enforcement boundary against untrusted repository content.
 *
 * <p>This tokenizes with {@link HclLexer} (a genuine lexer - strings, heredocs, and comments are
 * consumed as atomic units, so their contents can never be misread as structural punctuation) and
 * then recursive-descent parses a generic block/attribute tree ({@link Block}/{@link Value}) that
 * mirrors HCL's actual body grammar closely enough to track true nesting depth for ANY block or
 * object structure, not just the two shapes this class specifically interprets. Every other
 * attribute value (lists, function calls, references, arbitrary nested blocks) is still consumed
 * correctly (via balanced bracket/brace/paren counting) even though its content is discarded as
 * {@link Opaque} - this is what makes the parser structurally sound rather than heuristic: it can
 * never lose synchronization and silently skip past a {@code required_providers} or {@code module}
 * block it should have inspected.
 *
 * <p><b>Fail-closed contract:</b> the ONLY value shape ever accepted for a {@code source} attribute
 * (or a {@code required_providers} entry's shorthand string form) is an immediate, non-interpolated
 * string literal. A reference, function call, interpolation, heredoc, list, object, or any
 * malformed/unterminated syntax throws {@link TerraformConfigSourceExtractionException} - the
 * caller ({@link TerraformConfigSourceExtractor}) treats this as "cannot deterministically
 * understand this configuration," which {@link ControlledTerraformOperationCoordinator#executeInit}
 * turns into a hard block before {@code terraform init} is ever launched, never a silent omission.
 *
 * <p>Deliberately excludes the rest of the HCL expression language (full number/operator grammar,
 * conditionals, template directives beyond {@code ${...}} detection) - none of that is needed to
 * satisfy the fail-closed contract above, and implementing it would not change what this class
 * accepts as a valid {@code source} value.
 */
final class TerraformNativeSourceExtractor {

    private TerraformNativeSourceExtractor() {
    }

    static TerraformConfigSourceManifest extract(String content) {
        return extractKeyed(content).toManifest();
    }

    /** The built-in {@code terraform} provider (e.g. the {@code terraform_data} resource type) is
     * exempt from the implicit-provider-requirement check: it ships inside the Terraform binary
     * itself, real Terraform never requires (or even permits) a {@code required_providers} entry
     * for it, and it cannot be redirected to an arbitrary/attacker-controlled source - unlike every
     * other provider local name, which genuinely can be. */
    private static final String BUILTIN_PROVIDER_LOCAL_NAME = "terraform";

    static TerraformKeyedConfigSources extractKeyed(String content) {
        List<HclToken> tokens = HclLexer.tokenize(content);
        BodyResult top = parseBody(tokens, 0, true);

        Map<String, String> providerSourcesByLocalName = new LinkedHashMap<>();
        Map<String, String> moduleSourcesByLabel = new LinkedHashMap<>();
        Set<String> impliedProviderLocalNames = new LinkedHashSet<>();
        boolean declaresBackendBlock = false;
        boolean declaresRemoteStateDataSource = false;
        for (Block block : top.blocks()) {
            if (block.type().equals("terraform")) {
                for (Block child : block.children()) {
                    if (child.type().equals("required_providers")) {
                        for (Map.Entry<String, Value> entry : child.attributes().entrySet()) {
                            providerSourcesByLocalName.put(entry.getKey(), resolveProviderSource(entry.getKey(), entry.getValue()));
                        }
                    } else if (child.type().equals("backend")) {
                        // The repository may describe backend INTENT but must never establish
                        // backend AUTHORITY - see docs/phase-2b5-controlled-plan-state-read.md §5.
                        // Detected here (a fact the extractor reports), enforced by the coordinator
                        // (TERRAFORM_BACKEND_BLOCK_NOT_ALLOWED) - same division of responsibility as
                        // module-presence/implicit-provider checks.
                        declaresBackendBlock = true;
                    }
                }
            } else if (block.type().equals("module")) {
                if (block.labels().size() != 1) {
                    throw new TerraformConfigSourceExtractionException("a 'module' block must have exactly one label");
                }
                String label = block.labels().get(0);
                moduleSourcesByLabel.put(label, resolveModuleSource(label, block.attributes()));
            } else if (block.type().equals("resource") || block.type().equals("data")) {
                if (block.type().equals("data") && !block.labels().isEmpty() && block.labels().get(0).equals("terraform_remote_state")) {
                    // Terraform's built-in terraform_remote_state data source accepts its OWN
                    // backend/config coordinates, independent of TrustedBackendResolver - the exact
                    // state-boundary escape this check exists to close. See
                    // docs/phase-2b5-controlled-plan-state-read.md §5a.
                    declaresRemoteStateDataSource = true;
                }
                addImpliedProviderLocalName(impliedProviderLocalNames, effectiveProviderLocalNameFor(block.type(), block.labels(), block.attributes()));
            } else if (block.type().equals("provider")) {
                if (block.labels().size() == 1) {
                    addImpliedProviderLocalName(impliedProviderLocalNames, block.labels().get(0));
                }
            } else if (block.type().equals("import")) {
                Value providerAttr = block.attributes().get("provider");
                if (providerAttr != null) {
                    addImpliedProviderLocalName(impliedProviderLocalNames, resolveProviderReference(providerAttr, "'import' block"));
                }
                // No explicit `provider` meta-argument: an `import` block's implicit provider is
                // whatever the resource block its `to` address targets already establishes - that
                // resource block is independently walked and checked above, so nothing further is
                // needed here to avoid double-counting or under-counting.
            }
        }
        return new TerraformKeyedConfigSources(
                providerSourcesByLocalName, moduleSourcesByLabel, impliedProviderLocalNames, declaresBackendBlock, declaresRemoteStateDataSource);
    }

    /** Determines the provider local name Terraform will ACTUALLY use for a {@code resource}/
     * {@code data} block: an explicit {@code provider = localName} or {@code provider = localName.alias}
     * meta-argument, if present, always wins - the resource TYPE prefix is consulted only when no
     * such override exists. Requirement #1 of the final provider-binding amendment: a resource type
     * prefix must never be falsely treated as an implied dependency when an explicit {@code provider}
     * meta-argument already names the real one. */
    private static String effectiveProviderLocalNameFor(String blockType, List<String> labels, Map<String, Value> attributes) {
        Value providerAttr = attributes.get("provider");
        if (providerAttr != null) {
            return resolveProviderReference(providerAttr, "'" + blockType + "' " + String.join(" ", labels));
        }
        if (labels.isEmpty()) {
            throw new TerraformConfigSourceExtractionException("a '" + blockType + "' block must have a type label");
        }
        return impliedProviderFromResourceType(labels.get(0));
    }

    /** Accepts only a statically-recognizable {@code localName} or {@code localName.alias} provider
     * reference (requirement #2) - anything else (a function call, an index expression, a third
     * dotted segment, an interpolated/computed value, or any other shape this parser could not
     * capture as a clean identifier chain) fails closed rather than being silently treated as "no
     * override" or guessed at. */
    private static String resolveProviderReference(Value value, String describedAs) {
        if (value instanceof Reference reference && (reference.parts().size() == 1 || reference.parts().size() == 2)) {
            return reference.parts().get(0);
        }
        throw new TerraformConfigSourceExtractionException(
                describedAs + " has an unsupported 'provider' meta-argument reference - only localName or localName.alias is recognized");
    }

    private static void addImpliedProviderLocalName(Set<String> impliedProviderLocalNames, String localName) {
        if (!BUILTIN_PROVIDER_LOCAL_NAME.equals(localName)) {
            impliedProviderLocalNames.add(localName);
        }
    }

    /** Terraform's own convention: a resource/data TYPE is {@code <provider-local-name>_<rest>} -
     * e.g. {@code aws_instance} implies provider local name {@code "aws"}. Deliberately the simple
     * "up to the first underscore" rule rather than Terraform's full longest-declared-prefix
     * resolution algorithm (which consults the provider requirements THIS check exists to validate)
     * - a resource type that genuinely uses a different, non-conventional provider local name would
     * cause this check to require a {@code required_providers} entry under the computed name, which
     * fails closed (blocks) rather than silently under-enforcing; it can never cause a real implied
     * provider dependency to go unchecked in the direction that would matter (allowing something
     * that should have been blocked). */
    static String impliedProviderFromResourceType(String resourceType) {
        int underscore = resourceType.indexOf('_');
        return underscore <= 0 ? resourceType : resourceType.substring(0, underscore);
    }

    private static String resolveProviderSource(String localName, Value value) {
        if (value instanceof StringLiteral literal) {
            return requireLiteral(literal, "provider '" + localName + "'");
        }
        if (value instanceof ObjectValue object) {
            Value sourceValue = object.attributes().get("source");
            if (sourceValue == null) {
                // No explicit source: Terraform's own documented default namespace.
                return "registry.terraform.io/hashicorp/" + localName;
            }
            if (sourceValue instanceof StringLiteral literal) {
                return requireLiteral(literal, "provider '" + localName + "'");
            }
            throw new TerraformConfigSourceExtractionException("provider '" + localName + "' source is not a plain string literal");
        }
        throw new TerraformConfigSourceExtractionException("provider '" + localName + "' requirement is not a recognized shape");
    }

    private static String resolveModuleSource(String moduleLabel, Map<String, Value> attributes) {
        Value sourceValue = attributes.get("source");
        if (sourceValue == null) {
            throw new TerraformConfigSourceExtractionException("module '" + moduleLabel + "' has no extractable source");
        }
        if (sourceValue instanceof StringLiteral literal) {
            return requireLiteral(literal, "module '" + moduleLabel + "'");
        }
        throw new TerraformConfigSourceExtractionException("module '" + moduleLabel + "' source is not a plain string literal");
    }

    private static String requireLiteral(StringLiteral literal, String describedAs) {
        if (literal.hasInterpolation()) {
            throw new TerraformConfigSourceExtractionException(describedAs + " source uses interpolation/a heredoc, not a plain literal");
        }
        return literal.text();
    }

    // ===================== generic body/value parsing =====================

    private sealed interface Value permits StringLiteral, ObjectValue, Reference, Opaque {
    }

    private record StringLiteral(String text, boolean hasInterpolation) implements Value {
    }

    private record ObjectValue(Map<String, Value> attributes) implements Value {
    }

    /** A clean, statically-recognized dotted-identifier chain with no further trailing expression -
     * e.g. {@code corpaws} ({@code parts = ["corpaws"]}) or {@code corpaws.east}
     * ({@code parts = ["corpaws", "east"]}). Captured only when the chain is immediately followed by
     * end-of-statement (a newline or the enclosing body's closing brace) - anything more complex
     * (a function call, an index, a third segment, etc.) is deliberately left as {@link Opaque}
     * instead, so a caller checking for {@link Reference} never has to also confirm it isn't
     * secretly the head of something more complex. */
    private record Reference(List<String> parts) implements Value {
    }

    private record Opaque() implements Value {
    }

    private record Block(String type, List<String> labels, Map<String, Value> attributes, List<Block> children) {
    }

    private record BodyResult(Map<String, Value> attributes, List<Block> blocks, int endPos) {
    }

    private record ValueResult(Value value, int endPos) {
    }

    private static BodyResult parseBody(List<HclToken> tokens, int pos, boolean topLevel) {
        Map<String, Value> attrs = new LinkedHashMap<>();
        List<Block> blocks = new ArrayList<>();
        while (true) {
            while (tokens.get(pos).type() == HclToken.Type.NEWLINE) {
                pos++;
            }
            HclToken t = tokens.get(pos);
            if (t.type() == HclToken.Type.EOF) {
                if (!topLevel) {
                    throw new TerraformConfigSourceExtractionException("unterminated block - missing closing brace");
                }
                return new BodyResult(attrs, blocks, pos);
            }
            if (!topLevel && t.type() == HclToken.Type.RBRACE) {
                return new BodyResult(attrs, blocks, pos);
            }
            if (t.type() != HclToken.Type.IDENT) {
                pos++; // stray token at statement position - skip defensively, never affects source extraction
                continue;
            }
            String name = t.text();
            pos++;
            List<String> labels = new ArrayList<>();
            while (tokens.get(pos).type() == HclToken.Type.STRING) {
                labels.add(tokens.get(pos).text());
                pos++;
            }
            HclToken after = tokens.get(pos);
            if (after.type() == HclToken.Type.LBRACE) {
                pos++;
                BodyResult child = parseBody(tokens, pos, false);
                pos = child.endPos();
                if (tokens.get(pos).type() != HclToken.Type.RBRACE) {
                    throw new TerraformConfigSourceExtractionException("unterminated block - missing closing brace");
                }
                pos++;
                blocks.add(new Block(name, List.copyOf(labels), child.attributes(), child.blocks()));
            } else if (labels.isEmpty() && after.type() == HclToken.Type.EQUALS) {
                pos++;
                ValueResult value = parseValue(tokens, pos);
                pos = value.endPos();
                attrs.put(name, value.value());
            }
            // else: an identifier (optionally with labels) not followed by a block body or "=" -
            // an unrecognized statement shape. Already advanced past it; the loop simply continues
            // from here rather than guessing what it meant. This can never hide a real
            // required_providers/module block, since those are only ever recognized by their own
            // IDENT-then-LBRACE (or IDENT-then-EQUALS-then-object) shape being matched directly.
        }
    }

    private static ValueResult parseValue(List<HclToken> tokens, int pos) {
        HclToken t = tokens.get(pos);
        if (t.type() == HclToken.Type.STRING) {
            return new ValueResult(new StringLiteral(t.text(), t.hasInterpolation()), pos + 1);
        }
        if (t.type() == HclToken.Type.LBRACE) {
            pos++;
            BodyResult obj = parseBody(tokens, pos, false);
            pos = obj.endPos();
            if (tokens.get(pos).type() != HclToken.Type.RBRACE) {
                throw new TerraformConfigSourceExtractionException("unterminated object constructor - missing closing brace");
            }
            pos++;
            return new ValueResult(new ObjectValue(obj.attributes()), pos);
        }
        if (t.type() == HclToken.Type.LBRACKET) {
            return new ValueResult(new Opaque(), skipBalanced(tokens, pos, HclToken.Type.LBRACKET, HclToken.Type.RBRACKET));
        }
        if (t.type() == HclToken.Type.LPAREN) {
            return new ValueResult(new Opaque(), skipBalanced(tokens, pos, HclToken.Type.LPAREN, HclToken.Type.RPAREN));
        }
        if (t.type() == HclToken.Type.IDENT) {
            ValueResult reference = tryParseReferenceChain(tokens, pos);
            if (reference != null) {
                return reference;
            }
            // Falls through to opaque consumption below (starting at the original `pos`, unchanged) -
            // e.g. a bare "true"/"false"/"null", or an identifier chain that continues into a
            // function call, index, or further expression this parser does not need to understand.
        }
        // A bare/scalar expression (number, boolean, reference, ternary, string concatenation via
        // interpolation, function call chain, etc.) this class does not need to understand, since a
        // source attribute's value is NEVER accepted in this shape regardless. Consumed up to the
        // next depth-0 newline or the enclosing body's closing brace, tracking bracket/paren/brace
        // depth so a nested list/object/call within the expression is skipped correctly rather than
        // terminating early on its own internal punctuation.
        int depth = 0;
        while (true) {
            HclToken c = tokens.get(pos);
            if (c.type() == HclToken.Type.EOF) {
                return new ValueResult(new Opaque(), pos);
            }
            if (c.type() == HclToken.Type.LBRACE || c.type() == HclToken.Type.LBRACKET || c.type() == HclToken.Type.LPAREN) {
                depth++;
                pos++;
                continue;
            }
            if (c.type() == HclToken.Type.RBRACE || c.type() == HclToken.Type.RBRACKET || c.type() == HclToken.Type.RPAREN) {
                if (depth == 0) {
                    return new ValueResult(new Opaque(), pos);
                }
                depth--;
                pos++;
                continue;
            }
            if (depth == 0 && c.type() == HclToken.Type.NEWLINE) {
                pos++;
                return new ValueResult(new Opaque(), pos);
            }
            pos++;
        }
    }

    /** Attempts to read {@code pos} as a clean {@code IDENT ('.' IDENT)*} chain immediately followed
     * by end-of-statement (a {@code NEWLINE}, the enclosing body's {@code RBRACE}, or {@code EOF}).
     * Returns {@code null} (never partially advances the caller's notion of {@code pos} - the caller
     * must retry from the original position via the generic opaque path) if the chain does not end
     * cleanly there, e.g. it continues into {@code (}/{@code [} (a function call or index) or any
     * other token - those shapes are not a "provider reference" this parser accepts regardless, so
     * there is no need to partially capture them. */
    private static ValueResult tryParseReferenceChain(List<HclToken> tokens, int pos) {
        List<String> parts = new ArrayList<>();
        parts.add(tokens.get(pos).text());
        int p = pos + 1;
        while (tokens.get(p).type() == HclToken.Type.DOT && tokens.get(p + 1).type() == HclToken.Type.IDENT) {
            parts.add(tokens.get(p + 1).text());
            p += 2;
        }
        HclToken next = tokens.get(p);
        if (next.type() == HclToken.Type.NEWLINE) {
            return new ValueResult(new Reference(List.copyOf(parts)), p + 1);
        }
        if (next.type() == HclToken.Type.RBRACE || next.type() == HclToken.Type.EOF) {
            return new ValueResult(new Reference(List.copyOf(parts)), p);
        }
        return null;
    }

    private static int skipBalanced(List<HclToken> tokens, int pos, HclToken.Type open, HclToken.Type close) {
        int depth = 0;
        while (true) {
            HclToken t = tokens.get(pos);
            if (t.type() == HclToken.Type.EOF) {
                throw new TerraformConfigSourceExtractionException("unterminated bracket/parenthesis in configuration");
            }
            if (t.type() == open) {
                depth++;
            } else if (t.type() == close) {
                depth--;
            }
            pos++;
            if (depth == 0) {
                return pos;
            }
        }
    }
}
