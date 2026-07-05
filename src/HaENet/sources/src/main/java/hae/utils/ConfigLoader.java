package hae.utils;

import burp.api.montoya.MontoyaApi;
import hae.AppConstants;
import hae.utils.rule.model.RuleDefinition;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.representer.Representer;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class ConfigLoader {

    private final MontoyaApi api;
    private final Yaml yaml;
    private final String configFilePath;
    private final String templatesPath;
    private volatile Map<String, Object> configCache;

    public ConfigLoader(MontoyaApi api) {
        this.api = api;
        this.yaml = createSecureYaml();

        String configPath = determineConfigPath();
        this.configFilePath = String.format("%s/%s", configPath, "Config.yml");
        this.templatesPath = String.format("%s/%s", configPath, "templates");

        // 构造函数，初始化配置
        File configDir = new File(configPath);
        if (!(configDir.exists() && configDir.isDirectory())) {
            configDir.mkdirs();
        }

        File configFilePath = new File(this.configFilePath);
        if (!(configFilePath.exists() && configFilePath.isFile())) {
            initConfig();
        }

        File templatesDir = new File(this.templatesPath);
        if (!(templatesDir.exists() && templatesDir.isDirectory())) {
            initTemplates();
        }
    }

    private static boolean isValidConfigPath(String configPath) {
        File configPathFile = new File(configPath);
        return configPathFile.exists() && configPathFile.isDirectory();
    }

    private Yaml createSecureYaml() {
        // 配置 LoaderOptions 进行安全限制
        LoaderOptions loaderOptions = new LoaderOptions();
        // 禁用注释处理
        loaderOptions.setProcessComments(false);
        // 禁止递归键
        loaderOptions.setAllowRecursiveKeys(false);

        // 配置 DumperOptions 控制输出格式
        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);

        // 创建 Representer
        Representer representer = new Representer(dop);

        // 使用 SafeConstructor创建安全的 YAML 实例
        return new Yaml(new SafeConstructor(loaderOptions), representer, dop);
    }

    private String determineConfigPath() {
        // 优先级1：用户根目录
        String userConfigPath = String.format(
                "%s/.config/HaE",
                System.getProperty("user.home")
        );
        if (isValidConfigPath(userConfigPath)) {
            return userConfigPath;
        }

        // 优先级2：Jar包所在目录
        String jarPath = api.extension().filename();
        String jarDirectory = new File(jarPath).getParent();
        String jarConfigPath = String.format("%s/.config/HaE", jarDirectory);
        if (isValidConfigPath(jarConfigPath)) {
            return jarConfigPath;
        }

        return userConfigPath;
    }

    public void initConfig() {
        Map<String, Object> configMap = new LinkedHashMap<>();
        configMap.put("ExcludeSuffix", getExcludeSuffix());
        configMap.put("BlockHost", getBlockHost());
        configMap.put("ExcludeStatus", getExcludeStatus());
        configMap.put("LimitSize", getLimitSize());
        configMap.put("HaEScope", getScope());
        configMap.put("DynamicHeader", getDynamicHeader());

        try {
            Writer writer = new OutputStreamWriter(
                    Files.newOutputStream(Paths.get(configFilePath)),
                    StandardCharsets.UTF_8
            );
            yaml.dump(configMap, writer);
            writer.close();
        } catch (Exception e) {
            api
                    .logging()
                    .logToError("Failed to init config: " + e.getMessage());
        }
    }

    public String getRulesFilePath() {
        return templatesPath;
    }

    public String getTemplatesPath() {
        return templatesPath;
    }

    public Map<String, List<RuleDefinition>> getRules() {
        File templatesDir = new File(templatesPath);
        if (!templatesDir.exists()) {
            templatesDir.mkdirs();
        }
        return loadRulesFromTemplates(templatesDir);
    }

    private Map<String, List<RuleDefinition>> loadRulesFromTemplates(File templatesDir) {
        Map<String, List<RuleDefinition>> rules = new LinkedHashMap<>();

        File[] groupDirs = templatesDir.listFiles(File::isDirectory);
        if (groupDirs == null) return rules;

        for (File groupDir : groupDirs) {
            String groupName = groupDirToName(groupDir.getName());
            List<RuleDefinition> groupRules = new ArrayList<>();

            File[] yamlFiles = groupDir.listFiles(f -> f.getName().endsWith(".yaml") || f.getName().endsWith(".yml"));
            if (yamlFiles == null) continue;

            for (File yamlFile : yamlFiles) {
                try (InputStream in = Files.newInputStream(yamlFile.toPath())) {
                    Map<String, Object> tmpl = yaml.load(in);
                    if (tmpl != null && tmpl.containsKey("file")) {
                        groupRules.add(RuleDefinition.fromTemplateYaml(tmpl, groupName));
                    }
                } catch (Exception e) {
                    api.logging().logToError("Failed to load template " + yamlFile.getName() + ": " + e.getMessage());
                }
            }

            if (!groupRules.isEmpty()) {
                rules.put(groupName, groupRules);
            }
        }

        return rules;
    }

    private static String groupDirToName(String dirName) {
        switch (dirName) {
            case "fingerprint": return "Fingerprint";
            case "vulnerability": return "Maybe Vulnerability";
            case "basic-info": return "Basic Information";
            case "sensitive-info": return "Sensitive Information";
            case "other": return "Other";
            default:
                StringBuilder sb = new StringBuilder();
                for (String part : dirName.split("-")) {
                    if (!part.isEmpty()) {
                        sb.append(Character.toUpperCase(part.charAt(0)));
                        sb.append(part.substring(1));
                        sb.append(' ');
                    }
                }
                return sb.toString().trim();
        }
    }

    public static String groupNameToDir(String groupName) {
        switch (groupName) {
            case "Fingerprint": return "fingerprint";
            case "Maybe Vulnerability": return "vulnerability";
            case "Basic Information": return "basic-info";
            case "Sensitive Information": return "sensitive-info";
            case "Other": return "other";
            default:
                return groupName.toLowerCase().replace(' ', '-');
        }
    }

    public String getBlockHost() {
        return getValueFromConfig("BlockHost", AppConstants.host);
    }

    public void setBlockHost(String blockHost) {
        setValueToConfig("BlockHost", blockHost);
    }

    public String getExcludeSuffix() {
        return getValueFromConfig("ExcludeSuffix", AppConstants.suffix);
    }

    public void setExcludeSuffix(String excludeSuffix) {
        setValueToConfig("ExcludeSuffix", excludeSuffix);
    }

    public String getExcludeStatus() {
        return getValueFromConfig("ExcludeStatus", AppConstants.status);
    }

    public void setExcludeStatus(String status) {
        setValueToConfig("ExcludeStatus", status);
    }

    public String getDynamicHeader() {
        return getValueFromConfig("DynamicHeader", AppConstants.header);
    }

    public void setDynamicHeader(String header) {
        setValueToConfig("DynamicHeader", header);
    }

    public String getLimitSize() {
        return getValueFromConfig("LimitSize", AppConstants.size);
    }

    public void setLimitSize(String size) {
        setValueToConfig("LimitSize", size);
    }

    public String getScope() {
        return getValueFromConfig("HaEScope", AppConstants.scopeOptions);
    }

    public void setScope(String scope) {
        setValueToConfig("HaEScope", scope);
    }

    private String getValueFromConfig(String name, String defaultValue) {
        Map<String, Object> configData = getConfigData();
        if (configData != null && configData.containsKey(name)) {
            return configData.get(name).toString();
        }
        return defaultValue;
    }

    private Map<String, Object> getConfigData() {
        Map<String, Object> cached = configCache;
        if (cached != null) {
            return cached;
        }

        File yamlSetting = new File(configFilePath);
        if (!yamlSetting.exists() || !yamlSetting.isFile()) {
            return null;
        }

        try (
                InputStream inputStream = Files.newInputStream(
                        Paths.get(configFilePath)
                )
        ) {
            cached = yaml.load(inputStream);
            configCache = cached;
            return cached;
        } catch (Exception e) {
            api
                    .logging()
                    .logToError("Failed to load config: " + e.getMessage());
        }

        return null;
    }

    private void setValueToConfig(String name, String value) {
        Map<String, Object> currentConfig = loadCurrentConfig();
        currentConfig.put(name, value);

        try (
                Writer writer = new OutputStreamWriter(
                        Files.newOutputStream(Paths.get(configFilePath)),
                        StandardCharsets.UTF_8
                )
        ) {
            yaml.dump(currentConfig, writer);
            configCache = null; // 写入后失效缓存
        } catch (Exception e) {
            api
                    .logging()
                    .logToError("Failed to save config: " + e.getMessage());
        }
    }

    private Map<String, Object> loadCurrentConfig() {
        Path path = Paths.get(configFilePath);
        if (!Files.exists(path)) {
            return new LinkedHashMap<>(); // 返回空的Map，表示没有当前配置
        }

        try (InputStream in = Files.newInputStream(path)) {
            return yaml.load(in);
        } catch (Exception e) {
            return new LinkedHashMap<>(); // 读取失败时也返回空的Map
        }
    }

    public boolean initTemplates() {
        String[] groups = {"fingerprint", "vulnerability", "basic-info", "sensitive-info", "other"};
        boolean success = true;

        for (String group : groups) {
            File groupDir = new File(templatesPath, group);
            if (!groupDir.exists()) {
                groupDir.mkdirs();
            }

            String resourceBase = "templates/" + group + "/";
            try {
                InputStream indexStream = getClass().getClassLoader().getResourceAsStream(resourceBase + "index.txt");
                if (indexStream == null) continue;

                String content = new String(indexStream.readAllBytes(), StandardCharsets.UTF_8);
                for (String fileName : content.split("\n")) {
                    fileName = fileName.trim();
                    if (fileName.isEmpty()) continue;

                    InputStream fileStream = getClass().getClassLoader().getResourceAsStream(resourceBase + fileName);
                    if (fileStream == null) continue;

                    File target = new File(groupDir, fileName);
                    try (fileStream; OutputStream out = new FileOutputStream(target)) {
                        byte[] buffer = new byte[1024];
                        int len;
                        while ((len = fileStream.read(buffer)) > 0) {
                            out.write(buffer, 0, len);
                        }
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Failed to init templates for " + group + ": " + e.getMessage());
                success = false;
            }
        }

        if (!success) {
            api.logging().logToError("Template init failed");
        }
        return success;
    }
}
