package hae.utils.rule;

import burp.api.montoya.MontoyaApi;
import hae.AppConstants;
import hae.cache.DataCache;
import hae.repository.RuleRepository;
import hae.utils.ConfigLoader;
import hae.utils.rule.model.RuleDefinition;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.representer.Representer;

import java.io.File;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

public class RuleProcessor {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final RuleRepository ruleRepository;

    public RuleProcessor(MontoyaApi api, ConfigLoader configLoader, RuleRepository ruleRepository) {
        this.api = api;
        this.configLoader = configLoader;
        this.ruleRepository = ruleRepository;
    }

    public void rulesFormatAndSave() {
        DataCache.clear();

        String templatesPath = configLoader.getTemplatesPath();
        File templatesDir = new File(templatesPath);
        if (!templatesDir.exists()) {
            templatesDir.mkdirs();
        }
        saveAsTemplates(templatesDir);
    }

    private void saveAsTemplates(File templatesDir) {
        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        Representer representer = new Representer(dop);
        Yaml yaml = new Yaml(representer, dop);

        Set<String> writtenFiles = new java.util.HashSet<>();
        Set<String> activeGroupDirs = new java.util.HashSet<>();

        ruleRepository.getAll().forEach((groupName, rules) -> {
            String dirName = ConfigLoader.groupNameToDir(groupName);
            File groupDir = new File(templatesDir, dirName);
            if (!groupDir.exists()) {
                groupDir.mkdirs();
            }
            activeGroupDirs.add(groupDir.getAbsolutePath());

            for (RuleDefinition rule : rules) {
                Map<String, Object> tmpl = rule.toTemplateYaml(groupName);
                String fileName = slugify(rule.getName()) + ".yaml";
                File targetFile = new File(groupDir, fileName);
                writtenFiles.add(targetFile.getAbsolutePath());

                try (Writer writer = new java.io.OutputStreamWriter(
                        Files.newOutputStream(targetFile.toPath()), StandardCharsets.UTF_8)) {
                    yaml.dump(tmpl, writer);
                } catch (Exception e) {
                    api.logging().logToError("Failed to save template " + fileName + ": " + e.getMessage());
                }
            }
        });

        cleanOrphanFiles(templatesDir, writtenFiles, activeGroupDirs);
    }

    private void cleanOrphanFiles(File templatesDir, Set<String> writtenFiles, Set<String> activeGroupDirs) {
        File[] groupDirs = templatesDir.listFiles(File::isDirectory);
        if (groupDirs == null) return;

        for (File groupDir : groupDirs) {
            if (!activeGroupDirs.contains(groupDir.getAbsolutePath())) {
                deleteDirectory(groupDir);
                continue;
            }
            File[] files = groupDir.listFiles(f -> f.getName().endsWith(".yaml") || f.getName().endsWith(".yml"));
            if (files == null) continue;
            for (File f : files) {
                if (!writtenFiles.contains(f.getAbsolutePath())) {
                    f.delete();
                }
            }
        }
    }

    private static void deleteDirectory(File dir) {
        File[] files = dir.listFiles();
        if (files != null) {
            for (File f : files) f.delete();
        }
        dir.delete();
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

    public void changeRule(RuleDefinition rule, int select, String type) {
        ruleRepository.updateRule(type, select, rule);
        this.rulesFormatAndSave();
    }

    public void addRule(RuleDefinition rule, String type) {
        ruleRepository.addRule(type, rule);
        this.rulesFormatAndSave();
    }

    public void removeRule(int select, String type) {
        ruleRepository.removeRule(type, select);
        this.rulesFormatAndSave();
    }

    public void renameRuleGroup(String oldName, String newName) {
        ruleRepository.renameGroup(oldName, newName);
        this.rulesFormatAndSave();
    }

    public void deleteRuleGroup(String groupName) {
        ruleRepository.removeGroup(groupName);
        this.rulesFormatAndSave();
    }

    public String newRule() {
        int i = 0;
        String name = "New ";

        while (ruleRepository.containsGroup(name + i)) {
            i++;
        }

        ruleRepository.putGroup(name + i, new ArrayList<>(AppConstants.ruleTemplate));
        this.rulesFormatAndSave();
        return name + i;
    }
}
