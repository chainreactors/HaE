package hae.engine;

import java.util.Collections;
import java.util.List;

public class MatchResult {
    private final String name;
    private final String color;
    private final List<String> data;
    private final String scope;
    private final int count;

    public MatchResult(String name, String color, List<String> data, String scope, int count) {
        this.name = name != null ? name : "";
        this.color = color != null ? color : "";
        this.data = data != null ? Collections.unmodifiableList(data) : Collections.emptyList();
        this.scope = scope != null ? scope : "";
        this.count = count;
    }

    public String getName() { return name; }
    public String getColor() { return color; }
    public List<String> getData() { return data; }
    public String getScope() { return scope; }
    public int getCount() { return count; }
}
