package hae.instances.http.utils;

import burp.api.montoya.MontoyaApi;
import com.chainreactors.proton.hae.ProtonHaEEngine;
import com.chainreactors.proton.hae.model.MatchResult;
import hae.cache.DataCache;
import hae.engine.FingersEngine;
import hae.repository.DataRepository;
import hae.repository.RuleRepository;
import hae.service.ValidatorService;
import hae.utils.ConfigLoader;
import hae.utils.rule.model.RuleDefinition;
import hae.utils.string.HashCalculator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class RegularMatcher {

    private static final int HASH_FULL_LIMIT = 2 * 1024 * 1024;
    private static final int HASH_SAMPLE = 64 * 1024;

    private static final Set<String> FINGERPRINT_CONTENT_TYPES = Set.of(
            "text/html", "application/xhtml+xml", "application/xhtml"
    );

    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final DataRepository dataRepository;
    private final RuleRepository ruleRepository;

    private volatile ProtonHaEEngine protonEngine;
    private volatile FingersEngine fingersEngine;

    public RegularMatcher(
            MontoyaApi api,
            ConfigLoader configLoader,
            DataRepository dataRepository,
            RuleRepository ruleRepository
    ) {
        this.api = api;
        this.configLoader = configLoader;
        this.dataRepository = dataRepository;
        this.ruleRepository = ruleRepository;

        initProtonEngine();
        initFingersEngine();
    }

    private void initProtonEngine() {
        try {
            protonEngine = new ProtonHaEEngine();
            String rulesJson = buildRulesJson();
            if (rulesJson != null && !rulesJson.isEmpty()) {
                protonEngine.loadRules(rulesJson);
            }
            api.logging().logToOutput("[*] Proton engine loaded (version: " + protonEngine.version() + ")");
        } catch (Exception e) {
            api.logging().logToError("[!] Proton engine not available, falling back to Java regex: " + e.getMessage());
            protonEngine = null;
        }
    }

    private void initFingersEngine() {
        try {
            fingersEngine = new FingersEngine();
            api.logging().logToOutput("[*] Fingers engine loaded");
        } catch (Exception e) {
            api.logging().logToError("[!] Fingers engine not available: " + e.getMessage());
            fingersEngine = null;
        }
    }

    public void reloadProtonRules() {
        if (protonEngine != null) {
            try {
                String rulesJson = buildRulesJson();
                if (rulesJson != null && !rulesJson.isEmpty()) {
                    protonEngine.updateRules(rulesJson);
                }
            } catch (Exception e) {
                api.logging().logToError("[!] Proton rule reload failed: " + e.getMessage());
            }
        }
    }

    public Map<String, Map<String, Object>> performRegexMatching(
            String host,
            String url,
            String type,
            String message,
            String header,
            String body,
            boolean persist,
            boolean ignoreDataCache
    ) {
        String originalMessage = message;
        String dynamicHeader = configLoader.getDynamicHeader();

        if (!dynamicHeader.isBlank()) {
            String modifiedHeader = header.replaceAll(
                    String.format("(%s):.*?\r\n", configLoader.getDynamicHeader()),
                    ""
            );
            message = message.replace(header, modifiedHeader);
        }

        String messageIndex = computeMessageIndex(host, message);

        Map<String, Map<String, Object>> dataCacheMap = ignoreDataCache
                ? null
                : DataCache.get(messageIndex);

        if (dataCacheMap != null) {
            return dataCacheMap;
        }

        String firstLine = originalMessage.split("\\r?\\n", 2)[0];

        Map<String, Map<String, Object>> finalMap;
        if (protonEngine != null && protonEngine.isLoaded()) {
            finalMap = matchWithProton(host, url, type, firstLine, header, body, persist);
        } else {
            finalMap = applyMatchingRules(host, url, type, originalMessage, firstLine, header, body, persist);
        }

        // Fingers: only on response with HTML content-type
        if ("response".equals(type) || "any".equals(type)) {
            if (shouldRunFingers(header)) {
                appendFingersResults(finalMap, originalMessage, host, url, persist);
            }
        }

        DataCache.put(messageIndex, finalMap);
        return finalMap;
    }

    private boolean shouldRunFingers(String header) {
        if (fingersEngine == null || !fingersEngine.isLoaded()) return false;
        String lower = header.toLowerCase();
        int ct = lower.indexOf("content-type:");
        if (ct < 0) return true; // no content-type → try fingerprinting
        int end = lower.indexOf('\n', ct);
        if (end < 0) end = lower.length();
        String ctValue = lower.substring(ct + 13, end).trim();
        for (String allowed : FINGERPRINT_CONTENT_TYPES) {
            if (ctValue.contains(allowed)) return true;
        }
        return false;
    }

    private void appendFingersResults(
            Map<String, Map<String, Object>> finalMap,
            String rawMessage,
            String host,
            String url,
            boolean persist
    ) {
        try {
            List<FingersEngine.Framework> frameworks = fingersEngine.detect(
                    rawMessage.getBytes(StandardCharsets.UTF_8)
            );
            if (frameworks.isEmpty()) return;

            List<String> names = new ArrayList<>();
            for (FingersEngine.Framework fw : frameworks) {
                names.add(fw.toString());
            }

            Map<String, Object> tmpMap = new HashMap<>();
            tmpMap.put("color", "blue");
            tmpMap.put("data", String.join(hae.AppConstants.boundary, names));

            String key = String.format("[Fingers] (%d)", names.size());
            finalMap.put(key, tmpMap);

            if (persist) {
                dataRepository.mergeData(host, "[Fingers]", names, true);
            }
        } catch (Exception e) {
            api.logging().logToError("[!] Fingers detect error: " + e.getMessage());
        }
    }

    private Map<String, Map<String, Object>> matchWithProton(
            String host,
            String url,
            String type,
            String firstLine,
            String header,
            String body,
            boolean persist
    ) {
        Map<String, Map<String, Object>> finalMap = new ConcurrentHashMap<>();

        try {
            List<MatchResult> results = protonEngine.match(type, header, body, firstLine);

            for (MatchResult result : results) {
                String name = result.getName();
                String color = result.getColor();
                List<String> data = result.getData();

                if (data == null || data.isEmpty()) continue;

                Map<String, Object> tmpMap = new HashMap<>();
                tmpMap.put("color", color);
                tmpMap.put("data", String.join(hae.AppConstants.boundary, data));

                String nameAndSize = String.format("%s (%s)", name, data.size());
                finalMap.put(nameAndSize, tmpMap);

                String matchContent = firstLine + "\r\n" + header + "\r\n\r\n" + body;
                for (String match : data) {
                    ValidatorService.putContext(name, match, matchContent);
                    ValidatorService.putUrl(name, match, url);
                }

                if (persist) {
                    dataRepository.mergeData(host, name, new ArrayList<>(data), true);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[!] Proton match error: " + e.getMessage());
        }

        return finalMap;
    }

    // ─── Fallback: Java regex engine (kept for when proton is unavailable) ───

    private Map<String, Map<String, Object>> applyMatchingRules(
            String host,
            String url,
            String type,
            String message,
            String firstLine,
            String header,
            String body,
            boolean persist
    ) {
        Map<String, Map<String, Object>> finalMap = new ConcurrentHashMap<>();

        ruleRepository
                .getAllGroupNames()
                .parallelStream()
                .forEach(i -> {
                    for (RuleDefinition rule : ruleRepository.getRulesByGroup(i)) {
                        String matchContent = "";
                        List<String> result;
                        Map<String, Object> tmpMap = new HashMap<>();

                        boolean loaded = rule.isLoaded();
                        String name = rule.getName();
                        String firstRegex = rule.getFirstRegex();
                        String secondRegex = rule.getSecondRegex();
                        String format = rule.getFormat();
                        String color = rule.getColor();
                        String scope = rule.getScope();
                        boolean sensitive = rule.isSensitive();

                        if (
                                loaded &&
                                        (scope.contains(type) ||
                                                scope.contains("any") ||
                                                type.equals("any"))
                        ) {
                            switch (scope) {
                                case "any":
                                case "request":
                                case "response":
                                    matchContent = message;
                                    break;
                                case "any header":
                                case "request header":
                                case "response header":
                                    matchContent = header;
                                    break;
                                case "any body":
                                case "request body":
                                case "response body":
                                    matchContent = body;
                                    break;
                                case "request line":
                                case "response line":
                                    matchContent = firstLine;
                                    break;
                                default:
                                    break;
                            }

                            if (matchContent.isBlank()) {
                                continue;
                            }

                            try {
                                result = new ArrayList<>(
                                        javaRegexMatch(firstRegex, secondRegex, matchContent, format, sensitive)
                                );
                            } catch (Exception e) {
                                api.logging().logToError(
                                        String.format("[x] Error Info:\nName: %s\nRegex: %s", name, firstRegex)
                                );
                                continue;
                            }

                            Set<String> tmpSet = new LinkedHashSet<>(result);
                            result.clear();
                            result.addAll(tmpSet);

                            if (!result.isEmpty()) {
                                tmpMap.put("color", color);
                                tmpMap.put("data", String.join(hae.AppConstants.boundary, result));

                                String nameAndSize = String.format("%s (%s)", name, result.size());
                                finalMap.put(nameAndSize, tmpMap);

                                for (String match : result) {
                                    ValidatorService.putContext(name, match, matchContent);
                                    ValidatorService.putUrl(name, match, url);
                                }

                                if (persist) {
                                    dataRepository.mergeData(host, name, result, true);
                                }
                            }
                        }
                    }
                });

        return finalMap;
    }

    private List<String> javaRegexMatch(
            String firstRegex, String secondRegex, String content,
            String format, boolean sensitive
    ) {
        List<String> retList = new ArrayList<>();
        int flags = sensitive ? 0 : java.util.regex.Pattern.CASE_INSENSITIVE;
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(firstRegex, flags);
        java.util.regex.Matcher matcher = pattern.matcher(content);

        if (secondRegex.isEmpty()) {
            while (matcher.find()) {
                if (matcher.groupCount() > 0 && !matcher.group(1).isEmpty()) {
                    retList.add(matcher.group(1));
                }
            }
        } else {
            while (matcher.find()) {
                String matchContent = matcher.group(1);
                if (matchContent != null && !matchContent.isEmpty()) {
                    java.util.regex.Pattern sp = java.util.regex.Pattern.compile(secondRegex, flags);
                    java.util.regex.Matcher sm = sp.matcher(matchContent);
                    if (sm.find()) {
                        retList.add(matchContent);
                    }
                }
            }
        }
        return retList;
    }

    // ─── Helpers ───

    private String computeMessageIndex(String host, String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(host.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) '|');

            int len = message.length();
            if (len <= HASH_FULL_LIMIT) {
                digest.update(message.getBytes(StandardCharsets.UTF_8));
            } else {
                digest.update(Integer.toString(len).getBytes(StandardCharsets.UTF_8));
                digest.update((byte) '|');
                digest.update(message.substring(0, HASH_SAMPLE).getBytes(StandardCharsets.UTF_8));
                digest.update(message.substring(len - HASH_SAMPLE).getBytes(StandardCharsets.UTF_8));
            }
            return HashCalculator.bytesToHex(digest.digest());
        } catch (Exception e) {
            return "";
        }
    }

    private String buildRulesJson() {
        StringBuilder sb = new StringBuilder("{\"rules\":[");
        Set<String> groupNames = ruleRepository.getAllGroupNames();
        boolean firstGroup = true;

        for (String groupName : groupNames) {
            if (!firstGroup) sb.append(',');
            firstGroup = false;

            sb.append("{\"group\":\"").append(jsonEscape(groupName)).append("\",\"rule\":[");
            List<RuleDefinition> rules = ruleRepository.getRulesByGroup(groupName);
            boolean firstRule = true;

            for (RuleDefinition rule : rules) {
                if (!firstRule) sb.append(',');
                firstRule = false;

                sb.append("{\"name\":\"").append(jsonEscape(rule.getName())).append('"');
                sb.append(",\"loaded\":").append(rule.isLoaded());
                sb.append(",\"f_regex\":\"").append(jsonEscape(rule.getFirstRegex())).append('"');
                sb.append(",\"s_regex\":\"").append(jsonEscape(rule.getSecondRegex())).append('"');
                sb.append(",\"format\":\"").append(jsonEscape(rule.getFormat())).append('"');
                sb.append(",\"color\":\"").append(jsonEscape(rule.getColor())).append('"');
                sb.append(",\"scope\":\"").append(jsonEscape(rule.getScope())).append('"');
                sb.append(",\"engine\":\"").append(jsonEscape(rule.getEngine())).append('"');
                sb.append(",\"sensitive\":").append(rule.isSensitive());
                sb.append('}');
            }
            sb.append("]}");
        }
        sb.append("]}");
        return sb.toString();
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }
}
