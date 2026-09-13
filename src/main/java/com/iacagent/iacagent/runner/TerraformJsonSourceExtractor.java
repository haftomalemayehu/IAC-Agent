package com.iacagent.iacagent.runner;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Extracts {@code terraform.required_providers[*].source}/{@code module.*.source} from Terraform's
 * JSON configuration syntax ({@code *.tf.json}) - real, exact JSON parsing via this codebase's
 * established tree-parsing convention (never POJO/record data binding), not a heuristic scan. Since
 * {@code *.tf.json} content IS JSON, this class faces none of the ambiguity a native-syntax scanner
 * would - a JSON parser either succeeds with a well-defined tree or fails outright, and this class
 * fails closed ({@link TerraformConfigSourceExtractionException}) on anything it does not
 * specifically recognize as a plain JSON string in the position Terraform's JSON syntax spec
 * requires one, exactly like {@link TerraformNativeSourceExtractor} does for native syntax.
 *
 * <p>Terraform's JSON syntax represents a labeled block (like {@code module "foo" { ... }}) as a
 * nested object keyed by the label: {@code {"module": {"foo": {...}}}}. A block type that can
 * repeat may also appear as a JSON array of objects instead of a single object - both forms are
 * accepted here via {@link #asNodeList}.
 */
final class TerraformJsonSourceExtractor {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TerraformJsonSourceExtractor() {
    }

    static TerraformConfigSourceManifest extract(byte[] content) {
        return extractKeyed(content).toManifest();
    }

    static TerraformKeyedConfigSources extractKeyed(byte[] content) {
        JsonNode root;
        try {
            root = MAPPER.readTree(content);
        } catch (RuntimeException e) {
            throw new TerraformConfigSourceExtractionException("malformed *.tf.json content: " + e.getMessage());
        }
        if (root == null || !root.isObject()) {
            throw new TerraformConfigSourceExtractionException("*.tf.json root must be a JSON object");
        }

        Map<String, String> providerSourcesByLocalName = new LinkedHashMap<>();
        Map<String, String> moduleSourcesByLabel = new LinkedHashMap<>();
        boolean declaresBackendBlock = false;

        for (JsonNode terraformNode : asNodeList(root.path("terraform"))) {
            for (JsonNode requiredProvidersNode : asNodeList(terraformNode.path("required_providers"))) {
                if (!requiredProvidersNode.isObject()) {
                    throw new TerraformConfigSourceExtractionException("'required_providers' must be a JSON object keyed by provider local name");
                }
                for (String localName : requiredProvidersNode.propertyNames()) {
                    providerSourcesByLocalName.put(localName, resolveProviderSource(localName, requiredProvidersNode.path(localName)));
                }
            }
            JsonNode backendNode = terraformNode.path("backend");
            if (!backendNode.isMissingNode() && !backendNode.isNull()) {
                // Same rule as native syntax: the repository must never establish backend authority.
                declaresBackendBlock = true;
            }
        }

        JsonNode moduleNode = root.path("module");
        if (!moduleNode.isMissingNode() && !moduleNode.isNull()) {
            if (!moduleNode.isObject()) {
                throw new TerraformConfigSourceExtractionException("'module' must be a JSON object keyed by module name");
            }
            for (String moduleLabel : moduleNode.propertyNames()) {
                for (JsonNode moduleConfig : asNodeList(moduleNode.path(moduleLabel))) {
                    moduleSourcesByLabel.put(moduleLabel, resolveModuleSource(moduleLabel, moduleConfig));
                }
            }
        }

        Set<String> impliedProviderLocalNames = new LinkedHashSet<>();
        boolean declaresRemoteStateDataSource = false;
        for (String blockType : List.of("resource", "data")) {
            JsonNode typedNode = root.path(blockType);
            if (!typedNode.isObject()) {
                continue;
            }
            for (String resourceType : typedNode.propertyNames()) {
                if (blockType.equals("data") && resourceType.equals("terraform_remote_state")) {
                    // Same state-boundary-escape concern as the native-syntax equivalent - see
                    // TerraformConfigSourceManifest#declaresRemoteStateDataSource.
                    declaresRemoteStateDataSource = true;
                }
                JsonNode byName = typedNode.path(resourceType);
                if (!byName.isObject()) {
                    throw new TerraformConfigSourceExtractionException("'" + blockType + "." + resourceType + "' must be a JSON object keyed by resource name");
                }
                for (String resourceName : byName.propertyNames()) {
                    for (JsonNode instance : asNodeList(byName.path(resourceName))) {
                        addImpliedProviderLocalName(impliedProviderLocalNames, effectiveProviderLocalName(blockType, resourceType, instance));
                    }
                }
            }
        }
        JsonNode providerNode = root.path("provider");
        if (providerNode.isObject()) {
            for (String providerLabel : providerNode.propertyNames()) {
                addImpliedProviderLocalName(impliedProviderLocalNames, providerLabel);
            }
        }
        for (JsonNode importNode : asNodeList(root.path("import"))) {
            JsonNode importProvider = importNode.path("provider");
            if (!importProvider.isMissingNode() && !importProvider.isNull()) {
                addImpliedProviderLocalName(impliedProviderLocalNames, resolveProviderReference(importProvider, "'import' block"));
            }
            // No explicit `provider` key: the imported resource's own `resource` block (walked
            // above) already establishes whatever provider requirement applies - see the equivalent
            // native-syntax comment in TerraformNativeSourceExtractor.
        }

        return new TerraformKeyedConfigSources(providerSourcesByLocalName, moduleSourcesByLabel, impliedProviderLocalNames, declaresBackendBlock, declaresRemoteStateDataSource);
    }

    /** Determines the provider local name Terraform will ACTUALLY use for one {@code resource}/
     * {@code data} instance: an explicit {@code "provider": "localName"} or
     * {@code "provider": "localName.alias"} key, if present, always wins over the resource TYPE
     * prefix - the same rule, and the same reason, as {@link TerraformNativeSourceExtractor}'s
     * native-syntax equivalent. */
    private static String effectiveProviderLocalName(String blockType, String resourceType, JsonNode instance) {
        if (instance.isObject()) {
            JsonNode providerNode = instance.path("provider");
            if (!providerNode.isMissingNode() && !providerNode.isNull()) {
                return resolveProviderReference(providerNode, "'" + blockType + "." + resourceType + "'");
            }
        }
        return TerraformNativeSourceExtractor.impliedProviderFromResourceType(resourceType);
    }

    /** Accepts only a statically-recognizable {@code "localName"} or {@code "localName.alias"} JSON
     * string - anything else fails closed, exactly like the native-syntax equivalent. */
    private static String resolveProviderReference(JsonNode value, String describedAs) {
        if (value.isTextual()) {
            String[] parts = value.asText().split("\\.", -1);
            if ((parts.length == 1 || parts.length == 2) && java.util.Arrays.stream(parts).allMatch(TerraformJsonSourceExtractor::isValidIdentifier)) {
                return parts[0];
            }
        }
        throw new TerraformConfigSourceExtractionException(
                describedAs + " has an unsupported 'provider' meta-argument reference - only localName or localName.alias is recognized");
    }

    private static boolean isValidIdentifier(String candidate) {
        if (candidate.isEmpty() || !(Character.isLetter(candidate.charAt(0)) || candidate.charAt(0) == '_')) {
            return false;
        }
        return candidate.chars().allMatch(c -> Character.isLetterOrDigit(c) || c == '_' || c == '-');
    }

    private static void addImpliedProviderLocalName(Set<String> impliedProviderLocalNames, String localName) {
        if (!"terraform".equals(localName)) {
            impliedProviderLocalNames.add(localName);
        }
    }

    private static List<JsonNode> asNodeList(JsonNode node) {
        if (node.isMissingNode() || node.isNull()) {
            return List.of();
        }
        if (node.isArray()) {
            List<JsonNode> list = new ArrayList<>();
            node.forEach(list::add);
            return list;
        }
        return List.of(node);
    }

    private static String resolveProviderSource(String localName, JsonNode value) {
        if (value.isTextual()) {
            return value.asText();
        }
        if (value.isObject()) {
            JsonNode source = value.path("source");
            if (source.isMissingNode() || source.isNull()) {
                return "registry.terraform.io/hashicorp/" + localName;
            }
            if (source.isTextual()) {
                return source.asText();
            }
            throw new TerraformConfigSourceExtractionException("provider '" + localName + "' source is not a JSON string");
        }
        throw new TerraformConfigSourceExtractionException("provider '" + localName + "' requirement is not a recognized shape");
    }

    private static String resolveModuleSource(String moduleLabel, JsonNode config) {
        if (!config.isObject()) {
            throw new TerraformConfigSourceExtractionException("module '" + moduleLabel + "' body is not a recognized shape");
        }
        JsonNode source = config.path("source");
        if (source.isMissingNode() || source.isNull()) {
            throw new TerraformConfigSourceExtractionException("module '" + moduleLabel + "' has no extractable source");
        }
        if (!source.isTextual()) {
            throw new TerraformConfigSourceExtractionException("module '" + moduleLabel + "' source is not a JSON string");
        }
        return source.asText();
    }
}
