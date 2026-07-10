package hae.utils.rule.model;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class RuleDefinition {
    private boolean loaded;
    private String name;
    private String firstRegex;
    private String secondRegex;
    private String format;
    private String color;
    private String scope;
    private boolean sensitive;
    private String validator;
    private int validatorTimeout;
    private int validatorBulk;

    public RuleDefinition(boolean loaded, String name, String firstRegex, String secondRegex,
                          String format, String color, String scope, boolean sensitive,
                          String validator, int validatorTimeout, int validatorBulk) {
        this.loaded = loaded;
        this.name = name;
        this.firstRegex = firstRegex;
        this.secondRegex = secondRegex;
        this.format = format;
        this.color = color;
        this.scope = scope;
        this.sensitive = sensitive;
        this.validator = validator;
        this.validatorTimeout = validatorTimeout;
        this.validatorBulk = validatorBulk;
    }

    public static RuleDefinition fromObjectArray(Object[] objects) {
        return new RuleDefinition(
                (boolean) objects[0],
                (String) objects[1],
                (String) objects[2],
                (String) objects[3],
                (String) objects[4],
                (String) objects[5],
                (String) objects[6],
                (boolean) objects[7],
                (String) objects[8],
                (int) objects[9],
                (int) objects[10]
        );
    }

    public boolean isLoaded() { return loaded; }
    public void setLoaded(boolean loaded) { this.loaded = loaded; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getFirstRegex() { return firstRegex; }
    public void setFirstRegex(String firstRegex) { this.firstRegex = firstRegex; }

    public String getSecondRegex() { return secondRegex; }
    public void setSecondRegex(String secondRegex) { this.secondRegex = secondRegex; }

    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }

    public String getColor() { return color; }
    public void setColor(String color) { this.color = color; }

    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }

    public boolean isSensitive() { return sensitive; }
    public void setSensitive(boolean sensitive) { this.sensitive = sensitive; }

    public String getValidator() { return validator; }
    public void setValidator(String validator) { this.validator = validator; }

    public int getValidatorTimeout() { return validatorTimeout; }
    public void setValidatorTimeout(int validatorTimeout) { this.validatorTimeout = validatorTimeout; }

    public int getValidatorBulk() { return validatorBulk; }
    public void setValidatorBulk(int validatorBulk) { this.validatorBulk = validatorBulk; }

    public Object[] toObjectArray() {
        return new Object[]{loaded, name, firstRegex, secondRegex, format, color, scope, sensitive, validator, validatorTimeout, validatorBulk};
    }

    public static RuleDefinition fromTemplateYaml(Map<String, Object> tmpl, String group) {
        Map<String, Object> info = (Map<String, Object>) tmpl.getOrDefault("info", Map.of());
        Map<String, Object> meta = (Map<String, Object>) info.getOrDefault("metadata", Map.of());

        String fRegex = "";
        String sRegex = "";
        String format = "{0}";

        List<Map<String, Object>> fileList = (List<Map<String, Object>>) tmpl.get("file");
        if (fileList != null && !fileList.isEmpty()) {
            Map<String, Object> fileEntry = fileList.get(0);
            List<Map<String, Object>> extractors = (List<Map<String, Object>>) fileEntry.get("extractors");
            List<Map<String, Object>> matchers = (List<Map<String, Object>>) fileEntry.get("matchers");

            if (extractors != null && !extractors.isEmpty()) {
                Map<String, Object> ext = extractors.get(0);
                List<String> regexList = (List<String>) ext.get("regex");
                if (regexList != null && !regexList.isEmpty()) {
                    fRegex = regexList.get(0);
                }
                Object rg = ext.get("regex-group");
                if (rg != null) {
                    int g = ((Number) rg).intValue();
                    format = "{" + (g > 0 ? g - 1 : 0) + "}";
                }
            }

            if (matchers != null && !matchers.isEmpty()) {
                for (Map<String, Object> m : matchers) {
                    String mType = String.valueOf(m.getOrDefault("type", ""));
                    if ("regex".equals(mType)) {
                        List<String> mRegex = (List<String>) m.get("regex");
                        if (mRegex != null && !mRegex.isEmpty()) {
                            if (!fRegex.isEmpty()) {
                                sRegex = mRegex.get(0);
                            } else {
                                fRegex = mRegex.get(0);
                            }
                        }
                    }
                }
            }
        }

        boolean sensitive = Boolean.TRUE.equals(meta.getOrDefault("sensitive", false));
        if (!sensitive && fRegex.startsWith("(?i)")) {
            fRegex = fRegex.substring(4);
        }

        return new RuleDefinition(
                Boolean.TRUE.equals(meta.getOrDefault("loaded", true)),
                String.valueOf(info.getOrDefault("name", "")),
                fRegex,
                sRegex,
                format,
                String.valueOf(meta.getOrDefault("color", "gray")),
                String.valueOf(meta.getOrDefault("scope", "any")),
                sensitive,
                "", 0, 0
        );
    }

    public Map<String, Object> toTemplateYaml(String group) {
        String id = "hae-" + slugify(name);

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("color", color);
        meta.put("scope", scope);
        meta.put("sensitive", sensitive);
        meta.put("loaded", loaded);

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", name);
        info.put("severity", colorToSeverity(color));
        info.put("tags", "hae, " + slugify(group));
        info.put("metadata", meta);

        String pattern = firstRegex;
        if (!sensitive) {
            pattern = "(?i)" + pattern;
        }

        Map<String, Object> extractor = new LinkedHashMap<>();
        extractor.put("type", "regex");
        extractor.put("name", slugify(name));

        boolean hasSRegexExtractor = secondRegex != null && !secondRegex.isEmpty()
                && !"{0}".equals(format);

        if (hasSRegexExtractor) {
            extractor.put("regex", List.of(secondRegex));
            int rg = parseFormatGroup(format);
            if (rg != 1) {
                extractor.put("regex-group", rg);
            }
        } else {
            extractor.put("regex", List.of(pattern));
        }

        Map<String, Object> fileEntry = new LinkedHashMap<>();
        fileEntry.put("extensions", List.of("all"));

        if (hasSRegexExtractor) {
            Map<String, Object> matcher = new LinkedHashMap<>();
            matcher.put("type", "regex");
            matcher.put("regex", List.of(pattern));
            fileEntry.put("matchers", List.of(matcher));
        } else if (secondRegex != null && !secondRegex.isEmpty()) {
            Map<String, Object> matcher = new LinkedHashMap<>();
            matcher.put("type", "regex");
            matcher.put("regex", List.of(secondRegex));
            fileEntry.put("matchers", List.of(matcher));
        }

        fileEntry.put("extractors", List.of(extractor));

        Map<String, Object> tmpl = new LinkedHashMap<>();
        tmpl.put("id", id);
        tmpl.put("info", info);
        tmpl.put("file", List.of(fileEntry));
        return tmpl;
    }

    private static String slugify(String s) {
        if (s == null) return "unknown";
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') sb.append(c);
            else if (c >= 'A' && c <= 'Z') sb.append((char) (c + 32));
            else sb.append('-');
        }
        return sb.toString();
    }

    private static String colorToSeverity(String color) {
        if (color == null) return "info";
        switch (color) {
            case "red": return "critical";
            case "orange": return "high";
            case "yellow": return "medium";
            case "green": return "low";
            default: return "info";
        }
    }

    private static int parseFormatGroup(String format) {
        if (format == null || format.isEmpty() || "{0}".equals(format)) return 1;
        if (format.length() == 3 && format.charAt(0) == '{' && format.charAt(2) == '}') {
            return (format.charAt(1) - '0') + 1;
        }
        return 1;
    }
}
