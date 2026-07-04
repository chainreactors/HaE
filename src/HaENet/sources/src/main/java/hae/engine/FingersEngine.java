package hae.engine;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class FingersEngine implements AutoCloseable {

    private static NativeLib lib;
    private final AtomicInteger handle = new AtomicInteger(0);

    interface NativeLib extends Library {
        int FingersNewEngine();
        Pointer FingersDetect(int handle, byte[] data, int dataLen);
        void FingersFreeEngine(int handle);
        void ProtonFreeString(Pointer s);
    }

    public FingersEngine() {
        if (lib == null) {
            String explicit = System.getProperty("proton.hae.library.path");
            if (explicit != null && !explicit.isEmpty()) {
                lib = Native.load(explicit, NativeLib.class);
            } else {
                lib = Native.load("engine", NativeLib.class);
            }
        }
        int h = lib.FingersNewEngine();
        if (h <= 0) {
            throw new RuntimeException("failed to create fingers engine");
        }
        handle.set(h);
    }

    public FingersEngine(String nativeLibPath) {
        if (lib == null) {
            lib = Native.load(nativeLibPath, NativeLib.class);
        }
        int h = lib.FingersNewEngine();
        if (h <= 0) {
            throw new RuntimeException("failed to create fingers engine");
        }
        handle.set(h);
    }

    public List<Framework> detect(byte[] httpContent) {
        int h = handle.get();
        if (h <= 0) return Collections.emptyList();

        Pointer p = lib.FingersDetect(h, httpContent, httpContent.length);
        if (p == null) return Collections.emptyList();

        String json;
        try {
            json = p.getString(0, "UTF-8");
        } finally {
            lib.ProtonFreeString(p);
        }

        if (json == null || "[]".equals(json.trim())) {
            return Collections.emptyList();
        }

        return parseFrameworks(json);
    }

    public boolean isLoaded() {
        return handle.get() > 0;
    }

    @Override
    public void close() {
        int h = handle.getAndSet(0);
        if (h > 0 && lib != null) {
            lib.FingersFreeEngine(h);
        }
    }

    // ─── JSON parsing ───

    private static List<Framework> parseFrameworks(String json) {
        List<Framework> result = new ArrayList<>();
        int i = json.indexOf('[');
        if (i < 0) return result;
        i++;

        while (i < json.length()) {
            while (i < json.length() && (json.charAt(i) == ' ' || json.charAt(i) == ',' || json.charAt(i) == '\n')) i++;
            if (i >= json.length() || json.charAt(i) == ']') break;
            if (json.charAt(i) == '{') {
                int end = findBrace(json, i);
                if (end < 0) break;
                String obj = json.substring(i + 1, end);
                String name = extractStr(obj, "name");
                String version = extractStr(obj, "version");
                String from = extractStr(obj, "from");
                String tags = extractStr(obj, "tags");
                if (name != null && !name.isEmpty()) {
                    result.add(new Framework(name, version, from, tags));
                }
                i = end + 1;
            } else {
                i++;
            }
        }
        return result;
    }

    private static String extractStr(String obj, String key) {
        String needle = "\"" + key + "\"";
        int ki = obj.indexOf(needle);
        if (ki < 0) return null;
        int ci = obj.indexOf(':', ki + needle.length());
        if (ci < 0) return null;
        int vi = ci + 1;
        while (vi < obj.length() && obj.charAt(vi) == ' ') vi++;
        if (vi >= obj.length() || obj.charAt(vi) != '"') return null;
        int end = vi + 1;
        while (end < obj.length()) {
            if (obj.charAt(end) == '\\') { end += 2; continue; }
            if (obj.charAt(end) == '"') break;
            end++;
        }
        return obj.substring(vi + 1, end);
    }

    private static int findBrace(String s, int open) {
        int depth = 0;
        for (int i = open; i < s.length(); i++) {
            if (s.charAt(i) == '"') { for (i++; i < s.length() && s.charAt(i) != '"'; i++) { if (s.charAt(i) == '\\') i++; } continue; }
            if (s.charAt(i) == '{') depth++;
            if (s.charAt(i) == '}') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    public static class Framework {
        public final String name;
        public final String version;
        public final String from;
        public final String tags;

        public Framework(String name, String version, String from, String tags) {
            this.name = name != null ? name : "";
            this.version = version != null ? version : "";
            this.from = from != null ? from : "";
            this.tags = tags != null ? tags : "";
        }

        @Override
        public String toString() {
            if (version.isEmpty()) return name;
            return name + "/" + version;
        }
    }
}
