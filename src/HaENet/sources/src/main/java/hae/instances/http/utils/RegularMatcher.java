package hae.instances.http.utils;

import burp.api.montoya.MontoyaApi;
import hae.engine.ProtonEngine;
import hae.engine.MatchResult;
import hae.cache.DataCache;
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

    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final DataRepository dataRepository;
    private final RuleRepository ruleRepository;

    private volatile ProtonEngine protonEngine;

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
    }

    private void initProtonEngine() {
        try {
            protonEngine = new ProtonEngine();
            protonEngine.loadTemplateFiles(new java.io.File(configLoader.getTemplatesPath()));
            api.logging().logToOutput("[*] Proton engine loaded (version: " + protonEngine.version() + ")");
        } catch (Exception e) {
            api.logging().logToError("[!] Proton engine not available, falling back to Java regex: " + e.getMessage());
            protonEngine = null;
        }
    }

    public void reloadProtonRules() {
        if (protonEngine != null) {
            try {
                protonEngine.loadTemplateFiles(new java.io.File(configLoader.getTemplatesPath()));
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

        DataCache.put(messageIndex, finalMap);
        return finalMap;
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
                                        javaRegexMatch(firstRegex, secondRegex, matchContent, sensitive)
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
            boolean sensitive
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

}
