package hae.engine;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public class ProtonEngine implements AutoCloseable {

    private static final int FLAG_FULL_MATCH = 1;
    private static final int FLAG_SKIP_VALIDATION = 2;

    private interface NativeLib extends Library {
        Pointer ProtonVersion();
        int ProtonLoadTemplate(byte[] data, int length);
        Pointer ProtonFindAll(int handle, byte[] data, int dataLen, String label, int flags);
        void ProtonFreeScanner(int handle);
        void ProtonFreeString(Pointer s);
    }

    private final NativeLib lib;
    private final Map<String, ScopeScanner> scopeScanners = new LinkedHashMap<>();

    public ProtonEngine() {
        String explicit = System.getProperty("proton.hae.library.path");
        if (explicit != null && !explicit.isEmpty()) {
            lib = Native.load(explicit, NativeLib.class);
        } else {
            lib = Native.load("engine", NativeLib.class);
        }
    }

    public String version() {
        Pointer p = lib.ProtonVersion();
        try {
            return p.getString(0, "UTF-8");
        } finally {
            lib.ProtonFreeString(p);
        }
    }

    public void loadRules(String rulesJson) {
        close();
        List<HaERule> rules = parseRulesJson(rulesJson);
        buildScopeScanners(rules);
    }

    public void updateRules(String rulesJson) {
        loadRules(rulesJson);
    }

    public boolean isLoaded() {
        return !scopeScanners.isEmpty();
    }

    public List<MatchResult> match(String msgType, String header, String body, String firstLine) {
        List<MatchResult> results = new ArrayList<>();

        for (Map.Entry<String, ScopeScanner> entry : scopeScanners.entrySet()) {
            String scope = entry.getKey();
            ScopeScanner ss = entry.getValue();

            String content = resolveScope(scope, msgType, header, body, firstLine);
            if (content == null || content.isEmpty()) continue;

            byte[] data = content.getBytes(StandardCharsets.UTF_8);
            int handle = ss.handle.get();
            if (handle <= 0) continue;

            Pointer p = lib.ProtonFindAll(handle, data, data.length, "http",
                    FLAG_FULL_MATCH | FLAG_SKIP_VALIDATION);
            String json;
            try {
                json = p.getString(0, "UTF-8");
            } finally {
                lib.ProtonFreeString(p);
            }

            List<Finding> findings = parseFindings(json);
            for (Finding f : findings) {
                RuleMeta meta = ss.metaByName.get(f.templateName);
                if (meta == null) {
                    meta = new RuleMeta(f.templateName, "gray", scope, null);
                }

                Set<String> seen = new LinkedHashSet<>();
                for (String val : f.values) {
                    if (val == null || val.isEmpty()) continue;
                    if (meta.sRegex != null && !meta.sRegex.matcher(val).find()) continue;
                    seen.add(val);
                }
                if (!seen.isEmpty()) {
                    List<String> vals = new ArrayList<>(seen);
                    results.add(new MatchResult(meta.name, meta.color, vals, meta.scope, vals.size()));
                }
            }
        }

        return results;
    }

    @Override
    public void close() {
        for (ScopeScanner ss : scopeScanners.values()) {
            int h = ss.handle.getAndSet(0);
            if (h > 0) lib.ProtonFreeScanner(h);
        }
        scopeScanners.clear();
    }

    // ─── Internal: scope routing ───

    private static String resolveScope(String scope, String msgType,
                                       String header, String body, String firstLine) {
        switch (scope) {
            case "any":
                return firstLine + "\r\n" + header + "\r\n\r\n" + body;
            case "request":
                if (!"request".equals(msgType)) return null;
                return firstLine + "\r\n" + header + "\r\n\r\n" + body;
            case "response":
                if (!"response".equals(msgType)) return null;
                return firstLine + "\r\n" + header + "\r\n\r\n" + body;
            case "any-header": return header;
            case "request-header":
                return "request".equals(msgType) ? header : null;
            case "response-header":
                return "response".equals(msgType) ? header : null;
            case "any-body": return body;
            case "request-body":
                return "request".equals(msgType) ? body : null;
            case "response-body":
                return "response".equals(msgType) ? body : null;
            case "request-line":
                return "request".equals(msgType) ? firstLine : null;
            case "response-line":
                return "response".equals(msgType) ? firstLine : null;
            default:
                return firstLine + "\r\n" + header + "\r\n\r\n" + body;
        }
    }

    private static String normalizeScope(String scope) {
        if (scope == null) return "any";
        switch (scope) {
            case "any header": return "any-header";
            case "any body":   return "any-body";
            case "request header": return "request-header";
            case "request body":   return "request-body";
            case "request line":   return "request-line";
            case "response header": return "response-header";
            case "response body":   return "response-body";
            case "response line":   return "response-line";
            default: return scope;
        }
    }

    // ─── Internal: build scanners ───

    private void buildScopeScanners(List<HaERule> rules) {
        Map<String, List<HaERule>> grouped = new LinkedHashMap<>();
        for (HaERule r : rules) {
            String scope = normalizeScope(r.scope);
            grouped.computeIfAbsent(scope, k -> new ArrayList<>()).add(r);
        }

        for (Map.Entry<String, List<HaERule>> entry : grouped.entrySet()) {
            String scope = entry.getKey();
            List<HaERule> scopeRules = entry.getValue();

            String yaml = toProtonYAML(scopeRules);
            byte[] yamlBytes = yaml.getBytes(StandardCharsets.UTF_8);
            int handle = lib.ProtonLoadTemplate(yamlBytes, yamlBytes.length);
            if (handle <= 0) continue;

            Map<String, RuleMeta> meta = new LinkedHashMap<>();
            for (HaERule r : scopeRules) {
                Pattern sRegex = null;
                if (r.sRegex != null && !r.sRegex.isEmpty()) {
                    String sp = r.sRegex;
                    if (!r.sensitive) sp = "(?i)" + sp;
                    try { sRegex = Pattern.compile(sp); } catch (Exception ignored) {}
                }
                meta.put(r.name, new RuleMeta(r.name, r.color, scope, sRegex));
            }

            scopeScanners.put(scope, new ScopeScanner(new AtomicInteger(handle), meta));
        }
    }

    private static String toProtonYAML(List<HaERule> rules) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < rules.size(); i++) {
            if (i > 0) sb.append("\n---\n");
            HaERule r = rules.get(i);
            String pattern = r.fRegex;
            if (!r.sensitive) pattern = "(?i)" + pattern;
            int regexGroup = parseFormatGroup(r.format);

            sb.append("id: ").append(yamlQuote(slugify(r.name))).append('\n');
            sb.append("info:\n");
            sb.append("  name: ").append(yamlQuote(r.name)).append('\n');
            sb.append("  severity: ").append(colorToSeverity(r.color)).append('\n');
            sb.append("file:\n");
            sb.append("  - extensions:\n");
            sb.append("      - all\n");
            sb.append("    extractors:\n");
            sb.append("      - type: regex\n");
            sb.append("        regex:\n");
            sb.append("          - ").append(yamlQuote(pattern)).append('\n');
            sb.append("        regex-group: ").append(regexGroup).append('\n');
        }
        return sb.toString();
    }

    // ─── Internal: parse HaE JSON rules ───

    private static List<HaERule> parseRulesJson(String json) {
        List<HaERule> rules = new ArrayList<>();
        int pos = json.indexOf("\"rules\"");
        if (pos < 0) return rules;

        while (true) {
            int ruleStart = json.indexOf("\"f_regex\"", pos);
            if (ruleStart < 0) break;

            int objStart = json.lastIndexOf('{', ruleStart);
            int objEnd = findMatchingBrace(json, objStart);
            if (objEnd < 0) break;

            String obj = json.substring(objStart, objEnd + 1);
            if (!extractBool(obj, "loaded")) {
                pos = objEnd + 1;
                continue;
            }

            HaERule rule = new HaERule();
            rule.name = extractStr(obj, "name");
            rule.fRegex = unescapeJsonStr(extractStr(obj, "f_regex"));
            rule.sRegex = unescapeJsonStr(extractStr(obj, "s_regex"));
            rule.format = extractStr(obj, "format");
            rule.color = extractStr(obj, "color");
            rule.scope = extractStr(obj, "scope");
            rule.sensitive = extractBool(obj, "sensitive");
            rules.add(rule);

            pos = objEnd + 1;
        }
        return rules;
    }

    // ─── Internal: parse findings JSON from native ───

    private static List<Finding> parseFindings(String json) {
        List<Finding> results = new ArrayList<>();
        if (json == null || "[]".equals(json.trim())) return results;

        int i = json.indexOf('[');
        if (i < 0) return results;
        i++;

        while (i < json.length()) {
            while (i < json.length() && (json.charAt(i) == ' ' || json.charAt(i) == ',' || json.charAt(i) == '\n')) i++;
            if (i >= json.length() || json.charAt(i) == ']') break;
            if (json.charAt(i) == '{') {
                int end = findMatchingBrace(json, i);
                if (end < 0) break;
                String obj = json.substring(i + 1, end);
                String templateName = extractStr(obj, "template-name");
                if (templateName.isEmpty()) templateName = extractStr(obj, "templateName");

                List<String> values = new ArrayList<>();
                int eventsIdx = obj.indexOf("\"events\"");
                if (eventsIdx >= 0) {
                    int arrStart = obj.indexOf('[', eventsIdx);
                    if (arrStart >= 0) {
                        int arrEnd = findMatchingBracket(obj, arrStart);
                        if (arrEnd > 0) {
                            String evArr = obj.substring(arrStart + 1, arrEnd);
                            int ep = 0;
                            while (ep < evArr.length()) {
                                int evObjStart = evArr.indexOf('{', ep);
                                if (evObjStart < 0) break;
                                int evObjEnd = findMatchingBrace(evArr, evObjStart);
                                if (evObjEnd < 0) break;
                                String evObj = evArr.substring(evObjStart, evObjEnd + 1);
                                String val = extractStr(evObj, "value");
                                if (!val.isEmpty()) values.add(unescapeJsonStr(val));
                                ep = evObjEnd + 1;
                            }
                        }
                    }
                }

                if (!templateName.isEmpty()) {
                    results.add(new Finding(templateName, values));
                }
                i = end + 1;
            } else {
                i++;
            }
        }
        return results;
    }

    // ─── Utility methods ───

    private static int parseFormatGroup(String format) {
        if (format == null || format.isEmpty() || "{0}".equals(format)) return 1;
        if (format.length() == 3 && format.charAt(0) == '{' && format.charAt(2) == '}') {
            return (format.charAt(1) - '0') + 1;
        }
        return 1;
    }

    private static String colorToSeverity(String color) {
        if (color == null) return "info";
        switch (color) {
            case "red":    return "critical";
            case "orange": return "high";
            case "yellow": return "medium";
            case "green":  return "low";
            default:       return "info";
        }
    }

    private static String slugify(String s) {
        if (s == null) return "unknown";
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') sb.append(c);
            else if (c >= 'A' && c <= 'Z') sb.append((char)(c + 32));
            else sb.append('-');
        }
        return sb.toString();
    }

    private static String yamlQuote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String extractStr(String obj, String key) {
        String needle = "\"" + key + "\"";
        int ki = obj.indexOf(needle);
        if (ki < 0) return "";
        int ci = obj.indexOf(':', ki + needle.length());
        if (ci < 0) return "";
        int vi = ci + 1;
        while (vi < obj.length() && obj.charAt(vi) == ' ') vi++;
        if (vi >= obj.length() || obj.charAt(vi) != '"') return "";
        int end = vi + 1;
        while (end < obj.length()) {
            if (obj.charAt(end) == '\\') { end += 2; continue; }
            if (obj.charAt(end) == '"') break;
            end++;
        }
        return obj.substring(vi + 1, end);
    }

    private static boolean extractBool(String obj, String key) {
        String needle = "\"" + key + "\"";
        int ki = obj.indexOf(needle);
        if (ki < 0) return false;
        int ci = obj.indexOf(':', ki + needle.length());
        if (ci < 0) return false;
        int vi = ci + 1;
        while (vi < obj.length() && obj.charAt(vi) == ' ') vi++;
        return vi + 4 <= obj.length() && obj.substring(vi, vi + 4).equals("true");
    }

    private static String unescapeJsonStr(String s) {
        if (s == null || s.isEmpty()) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(++i);
                switch (next) {
                    case '"':  sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case 'n':  sb.append('\n'); break;
                    case 'r':  sb.append('\r'); break;
                    case 't':  sb.append('\t'); break;
                    default:   sb.append('\\'); sb.append(next);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static int findMatchingBrace(String s, int open) {
        int depth = 0;
        for (int i = open; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') {
                for (i++; i < s.length(); i++) {
                    if (s.charAt(i) == '\\') { i++; continue; }
                    if (s.charAt(i) == '"') break;
                }
                continue;
            }
            if (c == '{') depth++;
            if (c == '}') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    private static int findMatchingBracket(String s, int open) {
        int depth = 0;
        for (int i = open; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') {
                for (i++; i < s.length(); i++) {
                    if (s.charAt(i) == '\\') { i++; continue; }
                    if (s.charAt(i) == '"') break;
                }
                continue;
            }
            if (c == '[') depth++;
            if (c == ']') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    // ─── Internal data types ───

    private static final class HaERule {
        String name, fRegex, sRegex, format, color, scope;
        boolean sensitive;
    }

    private static final class Finding {
        final String templateName;
        final List<String> values;
        Finding(String templateName, List<String> values) {
            this.templateName = templateName;
            this.values = values;
        }
    }

    private static final class ScopeScanner {
        final AtomicInteger handle;
        final Map<String, RuleMeta> metaByName;
        ScopeScanner(AtomicInteger handle, Map<String, RuleMeta> metaByName) {
            this.handle = handle;
            this.metaByName = metaByName;
        }
    }

    private static final class RuleMeta {
        final String name, color, scope;
        final Pattern sRegex;
        RuleMeta(String name, String color, String scope, Pattern sRegex) {
            this.name = name;
            this.color = color;
            this.scope = scope;
            this.sRegex = sRegex;
        }
    }
}
