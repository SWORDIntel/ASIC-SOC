#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "asic_common.h"
#include "asic_telemetry.h"

#define ASIC_EDR_VERSION "0.2.0"
#define DEFAULT_CONFIG_PATH "/etc/asic-edr/rules.conf"
#define MAX_RULES 128
#define MAX_CMDLINE 512
#define MAX_RULE_ID 64
#define MAX_HOSTNAME 256
#define MAX_IDENTITY 128
#define DEFAULT_DEDUP_WINDOW_SECONDS 5ULL
#define FLOW_STATE_ENTRIES 256
#define FLOW_WINDOW_SECONDS 120U
#define JSONL_SCHEMA_VERSION "1"
#define FLOW_RULE_SHELL_DOWNLOADER_PUBLIC_NET "flow.shell_downloader_public_net"
#define FLOW_RULE_NO_TTY_PUBLIC_TRANSFER_TOOL "flow.no_tty_public_transfer_tool"
#define FLOW_RULE_SENSITIVE_READ_THEN_PUBLIC_NET "flow.sensitive_read_then_public_net"

static volatile sig_atomic_t stop = 0;
static struct bpf_link *links[5];

enum edr_severity {
    EDR_SEV_INFO = 0,
    EDR_SEV_WARN = 1,
    EDR_SEV_CRITICAL = 2,
};

enum edr_profile {
    EDR_PROFILE_BASELINE = 0,
    EDR_PROFILE_SERVER,
    EDR_PROFILE_DEVELOPER_WORKSTATION,
    EDR_PROFILE_HIGH_SIGNAL,
};

struct edr_finding {
    enum edr_severity severity;
    const char *rule_id;
    const char *reason;
    bool has_flow;
    const char *flow_id;
    uint32_t flow_score;
    const char *flow_reasons;
    uint32_t flow_window_seconds;
    uint32_t flow_root_pid;
};

struct edr_options {
    const char *config_path;
    const char *bpf_path;
    FILE *jsonl;
    bool console;
    bool all_events;
    bool check_config;
};

struct edr_rules {
    enum edr_profile profile;
    const char *profile_name;
    char suspicious_exec_exact[MAX_RULES][64];
    enum edr_severity suspicious_exec_exact_severity[MAX_RULES];
    char suspicious_exec_exact_rule_ids[MAX_RULES][MAX_RULE_ID];
    size_t suspicious_exec_exact_count;
    char suspicious_exec_prefix[MAX_RULES][64];
    enum edr_severity suspicious_exec_prefix_severity[MAX_RULES];
    char suspicious_exec_prefix_rule_ids[MAX_RULES][MAX_RULE_ID];
    size_t suspicious_exec_prefix_count;
    char sensitive_read[MAX_RULES][EDR_MAX_TARGET];
    enum edr_severity sensitive_read_severity[MAX_RULES];
    char sensitive_read_rule_ids[MAX_RULES][MAX_RULE_ID];
    size_t sensitive_read_count;
    char sensitive_write[MAX_RULES][EDR_MAX_TARGET];
    enum edr_severity sensitive_write_severity[MAX_RULES];
    char sensitive_write_rule_ids[MAX_RULES][MAX_RULE_ID];
    size_t sensitive_write_count;
    char jit_allow_comm[MAX_RULES][16];
    size_t jit_allow_comm_count;
    uint16_t suspicious_ports[MAX_RULES];
    enum edr_severity suspicious_port_severity[MAX_RULES];
    char suspicious_port_rule_ids[MAX_RULES][MAX_RULE_ID];
    size_t suspicious_port_count;
    char flow_allow_transfer[MAX_RULES][EDR_MAX_TARGET];
    size_t flow_allow_transfer_count;
    char disabled_rule_ids[MAX_RULES][MAX_RULE_ID];
    size_t disabled_rule_id_count;
    char severity_override_rule_ids[MAX_RULES][MAX_RULE_ID];
    enum edr_severity severity_override_values[MAX_RULES];
    size_t severity_override_count;
    uint64_t dedup_window_ns;
    enum edr_severity min_severity;
    enum edr_severity anon_exec_mmap_severity;
};

struct policy_summary {
    const char *profile_name;
    size_t suspicious_exec_exact_count;
    size_t suspicious_exec_prefix_count;
    size_t sensitive_read_count;
    size_t sensitive_write_count;
    size_t jit_allow_comm_count;
    size_t suspicious_port_count;
    size_t flow_allow_transfer_count;
    enum edr_severity min_severity;
    uint64_t dedup_window_seconds;
    enum edr_severity flow_sensitive_read_then_public_net_severity;
    uint32_t flow_sensitive_read_then_public_net_score;
    enum edr_severity flow_shell_downloader_public_net_severity;
    uint32_t flow_shell_downloader_public_net_score;
    enum edr_severity flow_no_tty_public_transfer_tool_severity;
    uint32_t flow_no_tty_public_transfer_tool_score;
};

struct agent_metadata {
    char schema_version[16];
    char agent_version[32];
    char hostname[MAX_HOSTNAME];
    char boot_id[MAX_IDENTITY];
    char agent_id[MAX_IDENTITY];
    char config_hash[32];
};

struct process_context {
    uint32_t ppid;
    uint32_t gppid;
    char parent_comm[16];
    char grandparent_comm[16];
    char exe[EDR_MAX_TARGET];
    char cwd[EDR_MAX_TARGET];
    char cmdline[MAX_CMDLINE];
    unsigned long long exe_dev;
    unsigned long long exe_inode;
    unsigned int exe_mode;
    unsigned int exe_uid;
    unsigned int exe_gid;
    long long exe_mtime;
    bool exe_deleted;
    bool exe_writable_path;
    bool has_tty;
    bool interactive_session;
};

struct dedup_entry {
    bool active;
    uint32_t type;
    uint32_t pid;
    uint32_t prot;
    uint32_t flags;
    uint32_t net_family;
    uint16_t net_port;
    uint64_t last_seen_ns;
    uint32_t repeat_count;
    struct edr_event event;
    char comm[16];
    char target[EDR_MAX_TARGET];
    const char *reason;
    const char *rule_id;
    enum edr_severity severity;
    bool has_flow;
    const char *flow_id;
    uint32_t flow_score;
    const char *flow_reasons;
    uint32_t flow_window_seconds;
    uint32_t flow_root_pid;
};

struct flow_state_entry {
    bool active;
    uint32_t root_pid;
    uint64_t last_seen_ns;
    bool shell_seen;
    bool transfer_exec_seen;
    bool sensitive_read_seen;
    bool public_connect_seen;
    uint32_t shell_pid;
    uint32_t transfer_pid;
    uint32_t sensitive_read_pid;
};

#define DEDUP_ENTRIES 128
#define NS_PER_SECOND (1000ULL * 1000ULL * 1000ULL)

static struct dedup_entry dedup_cache[DEDUP_ENTRIES];
static size_t dedup_cursor = 0;
static struct flow_state_entry flow_state[FLOW_STATE_ENTRIES];
static size_t flow_state_cursor = 0;
static struct edr_rules rules;
static struct agent_metadata agent_metadata;

static void sig_handler(int sig) {
    (void)sig;
    stop = 1;
}

static char *trim(char *value);
static void json_escape(FILE *out, const char *value);
static bool make_controlled_finding(enum edr_severity default_severity, const char *rule_id,
                                    const char *reason, struct edr_finding *finding);
static enum edr_severity compiled_flow_rule_severity(const char *rule_id);
static uint32_t default_flow_rule_score(const char *rule_id, bool suspicious_context);

static bool add_rule_value(char values[][64], enum edr_severity severities[],
                           char rule_ids[][MAX_RULE_ID], size_t *count,
                           size_t capacity, const char *value,
                           enum edr_severity severity, const char *rule_id) {
    if (*count >= capacity) {
        return false;
    }
    snprintf(values[*count], 64, "%s", value);
    severities[*count] = severity;
    snprintf(rule_ids[*count], MAX_RULE_ID, "%s", rule_id);
    (*count)++;
    return true;
}

static bool add_comm_rule(char values[][16], size_t *count, size_t capacity, const char *value) {
    if (*count >= capacity) {
        return false;
    }
    snprintf(values[*count], 16, "%s", value);
    (*count)++;
    return true;
}

static bool remove_rule_value(char values[][64], enum edr_severity severities[],
                              char rule_ids[][MAX_RULE_ID], size_t *count,
                              const char *value) {
    bool removed = false;
    for (size_t i = 0; i < *count;) {
        if (strcmp(values[i], value) == 0) {
            size_t tail = *count - i - 1;
            if (tail > 0) {
                memmove(&values[i], &values[i + 1], tail * sizeof(values[0]));
                memmove(&severities[i], &severities[i + 1], tail * sizeof(severities[0]));
                memmove(&rule_ids[i], &rule_ids[i + 1], tail * sizeof(rule_ids[0]));
            }
            (*count)--;
            removed = true;
            continue;
        }
        i++;
    }
    return removed;
}

static bool remove_path_rule(char values[][EDR_MAX_TARGET], enum edr_severity severities[],
                             char rule_ids[][MAX_RULE_ID], size_t *count, const char *value) {
    bool removed = false;
    for (size_t i = 0; i < *count;) {
        if (strcmp(values[i], value) == 0) {
            size_t tail = *count - i - 1;
            if (tail > 0) {
                memmove(&values[i], &values[i + 1], tail * sizeof(values[0]));
                memmove(&severities[i], &severities[i + 1], tail * sizeof(severities[0]));
                memmove(&rule_ids[i], &rule_ids[i + 1], tail * sizeof(rule_ids[0]));
            }
            (*count)--;
            removed = true;
            continue;
        }
        i++;
    }
    return removed;
}

static bool remove_comm_rule(char values[][16], size_t *count, const char *value) {
    bool removed = false;
    for (size_t i = 0; i < *count;) {
        if (strcmp(values[i], value) == 0) {
            size_t tail = *count - i - 1;
            if (tail > 0) {
                memmove(&values[i], &values[i + 1], tail * sizeof(values[0]));
            }
            (*count)--;
            removed = true;
            continue;
        }
        i++;
    }
    return removed;
}

static bool add_target_rule(char values[][EDR_MAX_TARGET], size_t *count,
                            size_t capacity, const char *value) {
    if (*count >= capacity) {
        return false;
    }
    snprintf(values[*count], EDR_MAX_TARGET, "%s", value);
    (*count)++;
    return true;
}

static bool remove_target_rule(char values[][EDR_MAX_TARGET], size_t *count,
                               const char *value) {
    bool removed = false;
    for (size_t i = 0; i < *count;) {
        if (strcmp(values[i], value) == 0) {
            size_t tail = *count - i - 1;
            if (tail > 0) {
                memmove(&values[i], &values[i + 1], tail * sizeof(values[0]));
            }
            (*count)--;
            removed = true;
            continue;
        }
        i++;
    }
    return removed;
}

static bool add_port_rule(uint16_t values[], enum edr_severity severities[],
                          char rule_ids[][MAX_RULE_ID], size_t *count,
                          size_t capacity, const char *value,
                          enum edr_severity severity, const char *rule_id) {
    if (*count >= capacity) {
        return false;
    }

    char *end = NULL;
    unsigned long port = strtoul(value, &end, 10);
    if (!end || *end != '\0' || port == 0 || port > 65535) {
        return false;
    }

    values[*count] = (uint16_t)port;
    severities[*count] = severity;
    snprintf(rule_ids[*count], MAX_RULE_ID, "%s", rule_id);
    (*count)++;
    return true;
}

static bool remove_port_rule(uint16_t values[], enum edr_severity severities[],
                             char rule_ids[][MAX_RULE_ID], size_t *count,
                             const char *value) {
    char *end = NULL;
    unsigned long port = strtoul(value, &end, 10);
    if (!end || *end != '\0' || port == 0 || port > 65535) {
        return false;
    }

    bool removed = false;
    for (size_t i = 0; i < *count;) {
        if (values[i] == (uint16_t)port) {
            size_t tail = *count - i - 1;
            if (tail > 0) {
                memmove(&values[i], &values[i + 1], tail * sizeof(values[0]));
                memmove(&severities[i], &severities[i + 1], tail * sizeof(severities[0]));
                memmove(&rule_ids[i], &rule_ids[i + 1], tail * sizeof(rule_ids[0]));
            }
            (*count)--;
            removed = true;
            continue;
        }
        i++;
    }
    return removed;
}

static bool parse_u64(const char *value, uint64_t *out) {
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        return false;
    }
    *out = (uint64_t)parsed;
    return true;
}

static bool parse_severity(const char *value, enum edr_severity *out) {
    if (strcmp(value, "info") == 0 || strcmp(value, "0") == 0) {
        *out = EDR_SEV_INFO;
        return true;
    }
    if (strcmp(value, "warn") == 0 || strcmp(value, "warning") == 0 || strcmp(value, "1") == 0) {
        *out = EDR_SEV_WARN;
        return true;
    }
    if (strcmp(value, "critical") == 0 || strcmp(value, "crit") == 0 || strcmp(value, "2") == 0) {
        *out = EDR_SEV_CRITICAL;
        return true;
    }
    return false;
}

static bool add_path_rule(char values[][EDR_MAX_TARGET], enum edr_severity severities[],
                          char rule_ids[][MAX_RULE_ID], size_t *count,
                          size_t capacity, const char *value,
                          enum edr_severity severity, const char *rule_id) {
    if (*count >= capacity) {
        return false;
    }
    snprintf(values[*count], EDR_MAX_TARGET, "%s", value);
    severities[*count] = severity;
    snprintf(rule_ids[*count], MAX_RULE_ID, "%s", rule_id);
    (*count)++;
    return true;
}

static struct policy_summary current_policy_summary(void) {
    return (struct policy_summary){
        .profile_name = rules.profile_name,
        .suspicious_exec_exact_count = rules.suspicious_exec_exact_count,
        .suspicious_exec_prefix_count = rules.suspicious_exec_prefix_count,
        .sensitive_read_count = rules.sensitive_read_count,
        .sensitive_write_count = rules.sensitive_write_count,
        .jit_allow_comm_count = rules.jit_allow_comm_count,
        .suspicious_port_count = rules.suspicious_port_count,
        .flow_allow_transfer_count = rules.flow_allow_transfer_count,
        .min_severity = rules.min_severity,
        .dedup_window_seconds = rules.dedup_window_ns / NS_PER_SECOND,
        .flow_sensitive_read_then_public_net_severity =
            compiled_flow_rule_severity(FLOW_RULE_SENSITIVE_READ_THEN_PUBLIC_NET),
        .flow_sensitive_read_then_public_net_score =
            default_flow_rule_score(FLOW_RULE_SENSITIVE_READ_THEN_PUBLIC_NET, false),
        .flow_shell_downloader_public_net_severity =
            compiled_flow_rule_severity(FLOW_RULE_SHELL_DOWNLOADER_PUBLIC_NET),
        .flow_shell_downloader_public_net_score =
            default_flow_rule_score(FLOW_RULE_SHELL_DOWNLOADER_PUBLIC_NET, false),
        .flow_no_tty_public_transfer_tool_severity =
            compiled_flow_rule_severity(FLOW_RULE_NO_TTY_PUBLIC_TRANSFER_TOOL),
        .flow_no_tty_public_transfer_tool_score =
            default_flow_rule_score(FLOW_RULE_NO_TTY_PUBLIC_TRANSFER_TOOL, false),
    };
}

static void trim_newline(char *value) {
    size_t len = strlen(value);
    while (len > 0 && (value[len - 1] == '\n' || value[len - 1] == '\r')) {
        value[--len] = '\0';
    }
}

static bool read_first_line_file(const char *path, char *out, size_t out_size) {
    if (!path || !out || out_size == 0) {
        return false;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        return false;
    }

    bool ok = fgets(out, out_size, f) != NULL;
    fclose(f);
    if (!ok) {
        out[0] = '\0';
        return false;
    }
    trim_newline(out);
    return out[0] != '\0';
}

static void compute_config_hash(const char *path, char *out, size_t out_size) {
    const uint64_t fnv_offset = 1469598103934665603ULL;
    const uint64_t fnv_prime = 1099511628211ULL;
    uint64_t hash = fnv_offset;
    FILE *f = path ? fopen(path, "rb") : NULL;

    if (f) {
        unsigned char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
            for (size_t i = 0; i < n; i++) {
                hash ^= buf[i];
                hash *= fnv_prime;
            }
        }
        fclose(f);
    } else {
        const char *fallback = "builtin-defaults";
        for (const unsigned char *p = (const unsigned char *)fallback; *p; p++) {
            hash ^= *p;
            hash *= fnv_prime;
        }
    }

    snprintf(out, out_size, "fnv1a64:%016llx", (unsigned long long)hash);
}

static void init_agent_metadata(const char *config_path) {
    memset(&agent_metadata, 0, sizeof(agent_metadata));
    snprintf(agent_metadata.schema_version, sizeof(agent_metadata.schema_version), "%s",
             JSONL_SCHEMA_VERSION);
    snprintf(agent_metadata.agent_version, sizeof(agent_metadata.agent_version), "%s",
             ASIC_EDR_VERSION);

    if (gethostname(agent_metadata.hostname, sizeof(agent_metadata.hostname)) != 0) {
        snprintf(agent_metadata.hostname, sizeof(agent_metadata.hostname), "unknown");
    }
    agent_metadata.hostname[sizeof(agent_metadata.hostname) - 1] = '\0';

    if (!read_first_line_file("/proc/sys/kernel/random/boot_id",
                              agent_metadata.boot_id,
                              sizeof(agent_metadata.boot_id))) {
        snprintf(agent_metadata.boot_id, sizeof(agent_metadata.boot_id), "unknown");
    }

    if (!read_first_line_file("/etc/machine-id",
                              agent_metadata.agent_id,
                              sizeof(agent_metadata.agent_id))) {
        snprintf(agent_metadata.agent_id, sizeof(agent_metadata.agent_id), "%.*s",
                 (int)sizeof(agent_metadata.agent_id) - 1,
                 agent_metadata.hostname);
    }

    compute_config_hash(config_path, agent_metadata.config_hash,
                        sizeof(agent_metadata.config_hash));
}

static void write_jsonl_metadata(FILE *out, const char *profile_name) {
    fprintf(out, "\"schema_version\":\"");
    json_escape(out, agent_metadata.schema_version);
    fprintf(out, "\",\"agent_id\":\"");
    json_escape(out, agent_metadata.agent_id);
    fprintf(out, "\",\"hostname\":\"");
    json_escape(out, agent_metadata.hostname);
    fprintf(out, "\",\"boot_id\":\"");
    json_escape(out, agent_metadata.boot_id);
    fprintf(out, "\",\"agent_version\":\"");
    json_escape(out, agent_metadata.agent_version);
    fprintf(out, "\",\"config_profile\":\"");
    json_escape(out, profile_name ? profile_name : "baseline");
    fprintf(out, "\",\"config_hash\":\"");
    json_escape(out, agent_metadata.config_hash);
    fprintf(out, "\"");
}

static void write_policy_summary_console(FILE *out, const struct policy_summary *summary,
                                         const char *prefix) {
    if (!out || !summary) {
        return;
    }

    fprintf(out,
            "%sprofile=%s exec_exact=%zu exec_prefix=%zu sensitive_read=%zu sensitive_write=%zu jit_allow=%zu suspicious_ports=%zu flow_allow_transfer=%zu min_severity=%d dedup_window_seconds=%llu flow_sensitive_read_then_public_net_severity=%d flow_sensitive_read_then_public_net_score=%u flow_shell_downloader_public_net_severity=%d flow_shell_downloader_public_net_score=%u flow_no_tty_public_transfer_tool_severity=%d flow_no_tty_public_transfer_tool_score=%u\n",
            prefix ? prefix : "",
            summary->profile_name ? summary->profile_name : "baseline",
            summary->suspicious_exec_exact_count,
            summary->suspicious_exec_prefix_count,
            summary->sensitive_read_count,
            summary->sensitive_write_count,
            summary->jit_allow_comm_count,
            summary->suspicious_port_count,
            summary->flow_allow_transfer_count,
            summary->min_severity,
            (unsigned long long)summary->dedup_window_seconds,
            summary->flow_sensitive_read_then_public_net_severity,
            summary->flow_sensitive_read_then_public_net_score,
            summary->flow_shell_downloader_public_net_severity,
            summary->flow_shell_downloader_public_net_score,
            summary->flow_no_tty_public_transfer_tool_severity,
            summary->flow_no_tty_public_transfer_tool_score);
}

static void write_policy_summary_jsonl(FILE *out, const struct policy_summary *summary) {
    if (!out || !summary) {
        return;
    }

    fprintf(out, "{\"record\":\"policy_summary\",");
    write_jsonl_metadata(out, summary->profile_name);
    fprintf(out, ",\"version\":\"%s\",\"profile\":\"", ASIC_EDR_VERSION);
    json_escape(out, summary->profile_name ? summary->profile_name : "baseline");
    fprintf(out,
            "\",\"exec_exact\":%zu,\"exec_prefix\":%zu,"
            "\"sensitive_read\":%zu,\"sensitive_write\":%zu,\"jit_allow\":%zu,"
            "\"suspicious_ports\":%zu,\"flow_allow_transfer\":%zu,"
            "\"min_severity\":%d,\"dedup_window_seconds\":%llu,"
            "\"flow_sensitive_read_then_public_net_severity\":%d,"
            "\"flow_sensitive_read_then_public_net_score\":%u,"
            "\"flow_shell_downloader_public_net_severity\":%d,"
            "\"flow_shell_downloader_public_net_score\":%u,"
            "\"flow_no_tty_public_transfer_tool_severity\":%d,"
            "\"flow_no_tty_public_transfer_tool_score\":%u}\n",
            summary->suspicious_exec_exact_count,
            summary->suspicious_exec_prefix_count,
            summary->sensitive_read_count,
            summary->sensitive_write_count,
            summary->jit_allow_comm_count,
            summary->suspicious_port_count,
            summary->flow_allow_transfer_count,
            summary->min_severity,
            (unsigned long long)summary->dedup_window_seconds,
            summary->flow_sensitive_read_then_public_net_severity,
            summary->flow_sensitive_read_then_public_net_score,
            summary->flow_shell_downloader_public_net_severity,
            summary->flow_shell_downloader_public_net_score,
            summary->flow_no_tty_public_transfer_tool_severity,
            summary->flow_no_tty_public_transfer_tool_score);
    fflush(out);
}

static bool valid_rule_id(const char *rule_id) {
    if (!rule_id || rule_id[0] == '\0') {
        return false;
    }
    if (strlen(rule_id) >= MAX_RULE_ID) {
        return false;
    }

    for (const unsigned char *p = (const unsigned char *)rule_id; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' || *p == '-')) {
            return false;
        }
    }
    return true;
}

static bool add_disabled_rule_id(const char *rule_id) {
    for (size_t i = 0; i < rules.disabled_rule_id_count; i++) {
        if (strcmp(rules.disabled_rule_ids[i], rule_id) == 0) {
            return true;
        }
    }
    if (rules.disabled_rule_id_count >= MAX_RULES) {
        return false;
    }
    snprintf(rules.disabled_rule_ids[rules.disabled_rule_id_count], MAX_RULE_ID, "%s", rule_id);
    rules.disabled_rule_id_count++;
    return true;
}

static bool add_rule_severity_override(const char *rule_id, enum edr_severity severity) {
    for (size_t i = 0; i < rules.severity_override_count; i++) {
        if (strcmp(rules.severity_override_rule_ids[i], rule_id) == 0) {
            rules.severity_override_values[i] = severity;
            return true;
        }
    }
    if (rules.severity_override_count >= MAX_RULES) {
        return false;
    }
    snprintf(rules.severity_override_rule_ids[rules.severity_override_count], MAX_RULE_ID, "%s", rule_id);
    rules.severity_override_values[rules.severity_override_count] = severity;
    rules.severity_override_count++;
    return true;
}

static bool rule_id_disabled(const char *rule_id) {
    for (size_t i = 0; i < rules.disabled_rule_id_count; i++) {
        if (strcmp(rules.disabled_rule_ids[i], rule_id) == 0) {
            return true;
        }
    }
    return false;
}

static enum edr_severity effective_rule_severity(const char *rule_id,
                                                 enum edr_severity default_severity) {
    for (size_t i = rules.severity_override_count; i > 0; i--) {
        size_t idx = i - 1;
        if (strcmp(rules.severity_override_rule_ids[idx], rule_id) == 0) {
            return rules.severity_override_values[idx];
        }
    }
    return default_severity;
}

static enum edr_severity default_flow_rule_severity(const char *rule_id) {
    if (strcmp(rule_id, FLOW_RULE_SENSITIVE_READ_THEN_PUBLIC_NET) == 0) {
        return EDR_SEV_CRITICAL;
    }
    if (strcmp(rule_id, FLOW_RULE_SHELL_DOWNLOADER_PUBLIC_NET) == 0) {
        return EDR_SEV_CRITICAL;
    }
    if (strcmp(rule_id, FLOW_RULE_NO_TTY_PUBLIC_TRANSFER_TOOL) == 0) {
        switch (rules.profile) {
        case EDR_PROFILE_SERVER:
        case EDR_PROFILE_HIGH_SIGNAL:
            return EDR_SEV_CRITICAL;
        case EDR_PROFILE_DEVELOPER_WORKSTATION:
            return EDR_SEV_INFO;
        case EDR_PROFILE_BASELINE:
            return EDR_SEV_WARN;
        }
    }
    return EDR_SEV_WARN;
}

static enum edr_severity compiled_flow_rule_severity(const char *rule_id) {
    return effective_rule_severity(rule_id, default_flow_rule_severity(rule_id));
}

static uint32_t default_flow_rule_score(const char *rule_id, bool suspicious_context) {
    if (strcmp(rule_id, FLOW_RULE_SENSITIVE_READ_THEN_PUBLIC_NET) == 0) {
        return suspicious_context ? 95U : 90U;
    }
    if (strcmp(rule_id, FLOW_RULE_SHELL_DOWNLOADER_PUBLIC_NET) == 0) {
        return 90U;
    }
    if (strcmp(rule_id, FLOW_RULE_NO_TTY_PUBLIC_TRANSFER_TOOL) == 0) {
        switch (rules.profile) {
        case EDR_PROFILE_SERVER:
        case EDR_PROFILE_HIGH_SIGNAL:
            return 90U;
        case EDR_PROFILE_DEVELOPER_WORKSTATION:
            return 40U;
        case EDR_PROFILE_BASELINE:
            return 70U;
        }
    }
    return 0U;
}

static bool rule_controls_allow(const char *rule_id, enum edr_severity default_severity,
                                enum edr_severity *severity) {
    if (rule_id_disabled(rule_id)) {
        return false;
    }
    *severity = effective_rule_severity(rule_id, default_severity);
    return true;
}

static bool parse_rule_severity_control(char *raw_value, const char **rule_id,
                                        enum edr_severity *severity) {
    char *comma = strchr(raw_value, ',');
    if (!comma) {
        return false;
    }
    *comma = '\0';
    char *id = trim(raw_value);
    char *severity_value = trim(comma + 1);
    if (!valid_rule_id(id) || !parse_severity(severity_value, severity)) {
        return false;
    }
    *rule_id = id;
    return true;
}

static bool split_rule_value(char *raw_value, enum edr_severity default_severity,
                             const char *default_rule_id, char **rule_value,
                             enum edr_severity *severity, const char **rule_id) {
    *severity = default_severity;
    *rule_id = default_rule_id;
    char *comma = strrchr(raw_value, ',');
    if (comma) {
        *comma = '\0';
        char *suffix = trim(comma + 1);
        if (parse_severity(suffix, severity)) {
            *rule_id = default_rule_id;
        } else {
            if (!valid_rule_id(suffix)) {
                return false;
            }
            char *severity_comma = strrchr(raw_value, ',');
            if (!severity_comma) {
                return false;
            }
            *severity_comma = '\0';
            char *severity_value = trim(severity_comma + 1);
            if (!parse_severity(severity_value, severity)) {
                return false;
            }
            *rule_id = suffix;
        }
    }

    *rule_value = trim(raw_value);
    return (*rule_value)[0] != '\0';
}

static bool rule_id_in_string_rules(char rule_ids[][MAX_RULE_ID], size_t count,
                                    const char *rule_id) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(rule_ids[i], rule_id) == 0) {
            return true;
        }
    }
    return false;
}

static bool rule_id_matches_family(const char *rule_id, const char *family) {
    size_t family_len = strlen(family);
    size_t rule_len = strlen(rule_id);
    if (rule_len == family_len) {
        return strcmp(rule_id, family) == 0;
    }
    return rule_len > family_len && strncmp(rule_id, family, family_len) == 0 &&
           rule_id[family_len] == '.';
}

static bool known_rule_id(const char *rule_id) {
    static const char *memory_rule_ids[] = {
        "mem.rwx_mprotect",
        "mem.exec_mprotect",
        "mem.rwx_mmap",
        "mem.anon_exec_mmap",
    };
    static const char *flow_rule_ids[] = {
        FLOW_RULE_SHELL_DOWNLOADER_PUBLIC_NET,
        FLOW_RULE_NO_TTY_PUBLIC_TRANSFER_TOOL,
        FLOW_RULE_SENSITIVE_READ_THEN_PUBLIC_NET,
    };

    for (size_t i = 0; i < sizeof(memory_rule_ids) / sizeof(memory_rule_ids[0]); i++) {
        if (strcmp(memory_rule_ids[i], rule_id) == 0) {
            return true;
        }
    }
    for (size_t i = 0; i < sizeof(flow_rule_ids) / sizeof(flow_rule_ids[0]); i++) {
        if (strcmp(flow_rule_ids[i], rule_id) == 0) {
            return true;
        }
    }
    return rule_id_in_string_rules(rules.suspicious_exec_exact_rule_ids,
                                   rules.suspicious_exec_exact_count, rule_id) ||
           rule_id_in_string_rules(rules.suspicious_exec_prefix_rule_ids,
                                   rules.suspicious_exec_prefix_count, rule_id) ||
           rule_id_in_string_rules(rules.sensitive_read_rule_ids,
                                   rules.sensitive_read_count, rule_id) ||
           rule_id_in_string_rules(rules.sensitive_write_rule_ids,
                                   rules.sensitive_write_count, rule_id) ||
           rule_id_in_string_rules(rules.suspicious_port_rule_ids,
                                   rules.suspicious_port_count, rule_id);
}

static bool validate_rule_id_controls(const char *path) {
    bool valid = true;
    for (size_t i = 0; i < rules.disabled_rule_id_count; i++) {
        if (!known_rule_id(rules.disabled_rule_ids[i])) {
            fprintf(stderr, "unknown disable_rule_id '%s' in %s\n", rules.disabled_rule_ids[i], path);
            valid = false;
        }
    }
    for (size_t i = 0; i < rules.severity_override_count; i++) {
        if (!known_rule_id(rules.severity_override_rule_ids[i])) {
            fprintf(stderr, "unknown rule_severity rule_id '%s' in %s\n",
                    rules.severity_override_rule_ids[i], path);
            valid = false;
        }
    }
    return valid;
}

static const char *profile_name(enum edr_profile profile) {
    switch (profile) {
    case EDR_PROFILE_BASELINE:
        return "baseline";
    case EDR_PROFILE_SERVER:
        return "server";
    case EDR_PROFILE_DEVELOPER_WORKSTATION:
        return "developer-workstation";
    case EDR_PROFILE_HIGH_SIGNAL:
        return "high-signal";
    }
    return "baseline";
}

static bool parse_profile(const char *value, enum edr_profile *profile) {
    if (strcmp(value, "baseline") == 0) {
        *profile = EDR_PROFILE_BASELINE;
        return true;
    }
    if (strcmp(value, "server") == 0) {
        *profile = EDR_PROFILE_SERVER;
        return true;
    }
    if (strcmp(value, "developer-workstation") == 0) {
        *profile = EDR_PROFILE_DEVELOPER_WORKSTATION;
        return true;
    }
    if (strcmp(value, "high-signal") == 0) {
        *profile = EDR_PROFILE_HIGH_SIGNAL;
        return true;
    }
    return false;
}

static bool string_rule_present(char values[][64], size_t count, const char *value) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(values[i], value) == 0) {
            return true;
        }
    }
    return false;
}

static bool add_profile_exec_exact_if_missing(const char *value) {
    if (string_rule_present(rules.suspicious_exec_exact,
                            rules.suspicious_exec_exact_count, value)) {
        return true;
    }
    return add_rule_value(rules.suspicious_exec_exact, rules.suspicious_exec_exact_severity,
                          rules.suspicious_exec_exact_rule_ids,
                          &rules.suspicious_exec_exact_count, MAX_RULES,
                          value, EDR_SEV_WARN, "exec.suspicious_exact");
}

static bool apply_profile(enum edr_profile profile) {
    rules.profile = profile;
    rules.profile_name = profile_name(profile);

    switch (profile) {
    case EDR_PROFILE_BASELINE:
        return true;
    case EDR_PROFILE_SERVER:
        remove_comm_rule(rules.jit_allow_comm, &rules.jit_allow_comm_count, "chrome");
        remove_comm_rule(rules.jit_allow_comm, &rules.jit_allow_comm_count, "chromium");
        remove_comm_rule(rules.jit_allow_comm, &rules.jit_allow_comm_count, "firefox");
        return add_profile_exec_exact_if_missing("curl") &&
               add_profile_exec_exact_if_missing("wget");
    case EDR_PROFILE_DEVELOPER_WORKSTATION:
        rules.anon_exec_mmap_severity = EDR_SEV_INFO;
        return true;
    case EDR_PROFILE_HIGH_SIGNAL:
        remove_rule_value(rules.suspicious_exec_exact, rules.suspicious_exec_exact_severity,
                          rules.suspicious_exec_exact_rule_ids,
                          &rules.suspicious_exec_exact_count, "bash");
        remove_rule_value(rules.suspicious_exec_exact, rules.suspicious_exec_exact_severity,
                          rules.suspicious_exec_exact_rule_ids,
                          &rules.suspicious_exec_exact_count, "sh");
        return true;
    }
    return false;
}

static void init_default_rules(void) {
    memset(&rules, 0, sizeof(rules));
    rules.profile = EDR_PROFILE_BASELINE;
    rules.profile_name = profile_name(EDR_PROFILE_BASELINE);
    rules.dedup_window_ns = DEFAULT_DEDUP_WINDOW_SECONDS * NS_PER_SECOND;
    rules.min_severity = EDR_SEV_WARN;
    rules.anon_exec_mmap_severity = EDR_SEV_WARN;

    const char *exec_exact[] = {
        "bash", "sh", "dash", "zsh", "curl", "wget", "nc", "ncat", "socat", "pkexec", "sudo",
    };
    const char *exec_prefix[] = {
        "python", "perl", "ruby",
    };
    const char *read_paths[] = {
        "/etc/shadow", "/etc/sudoers", "/etc/ssh/", "/root/.ssh/",
        "/.ssh/id_rsa", "/.ssh/id_ed25519", "/proc/kcore",
    };
    const char *write_paths[] = {
        "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers", "/etc/ssh/",
        "/root/.ssh/", "/.ssh/", "/etc/systemd/system/", "/etc/cron.", "/etc/crontab",
    };
    const char *jit_allow[] = {
        "node", "chrome", "chromium", "firefox", "java",
    };
    const char *ports[] = {
        "4444", "5555", "6666", "6667", "1337", "31337",
    };

    for (size_t i = 0; i < sizeof(exec_exact) / sizeof(exec_exact[0]); i++) {
        add_rule_value(rules.suspicious_exec_exact, rules.suspicious_exec_exact_severity,
                       rules.suspicious_exec_exact_rule_ids, &rules.suspicious_exec_exact_count,
                       MAX_RULES, exec_exact[i], EDR_SEV_WARN, "exec.suspicious_exact");
    }
    for (size_t i = 0; i < sizeof(exec_prefix) / sizeof(exec_prefix[0]); i++) {
        add_rule_value(rules.suspicious_exec_prefix, rules.suspicious_exec_prefix_severity,
                       rules.suspicious_exec_prefix_rule_ids, &rules.suspicious_exec_prefix_count,
                       MAX_RULES, exec_prefix[i], EDR_SEV_WARN, "exec.suspicious_prefix");
    }
    for (size_t i = 0; i < sizeof(read_paths) / sizeof(read_paths[0]); i++) {
        add_path_rule(rules.sensitive_read, rules.sensitive_read_severity,
                      rules.sensitive_read_rule_ids, &rules.sensitive_read_count,
                      MAX_RULES, read_paths[i], EDR_SEV_WARN, "file.sensitive_read");
    }
    for (size_t i = 0; i < sizeof(write_paths) / sizeof(write_paths[0]); i++) {
        add_path_rule(rules.sensitive_write, rules.sensitive_write_severity,
                      rules.sensitive_write_rule_ids, &rules.sensitive_write_count,
                      MAX_RULES, write_paths[i], EDR_SEV_CRITICAL, "file.sensitive_write");
    }
    for (size_t i = 0; i < sizeof(jit_allow) / sizeof(jit_allow[0]); i++) {
        add_comm_rule(rules.jit_allow_comm, &rules.jit_allow_comm_count, MAX_RULES, jit_allow[i]);
    }
    for (size_t i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
        add_port_rule(rules.suspicious_ports, rules.suspicious_port_severity,
                      rules.suspicious_port_rule_ids, &rules.suspicious_port_count,
                      MAX_RULES, ports[i], EDR_SEV_WARN, "net.suspicious_port");
    }
}

static char *trim(char *value) {
    while (*value == ' ' || *value == '\t' || *value == '\n' || *value == '\r') {
        value++;
    }
    char *end = value + strlen(value);
    while (end > value && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n' || end[-1] == '\r')) {
        *--end = '\0';
    }
    return value;
}

static bool select_profile_from_file(FILE *f, const char *path) {
    char line[512];
    unsigned int line_no = 0;
    enum edr_profile selected = EDR_PROFILE_BASELINE;
    bool valid = true;

    while (fgets(line, sizeof(line), f)) {
        line_no++;
        char *entry = trim(line);
        if (entry[0] == '\0' || entry[0] == '#') {
            continue;
        }

        char *eq = strchr(entry, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';
        char *key = trim(entry);
        char *value = trim(eq + 1);
        if (strcmp(key, "profile") != 0) {
            continue;
        }
        if (!parse_profile(value, &selected)) {
            fprintf(stderr,
                    "invalid profile '%s' on line %u in %s; supported profiles: baseline, server, developer-workstation, high-signal\n",
                    value, line_no, path);
            valid = false;
        }
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "failed to rewind config %s: %s\n", path, strerror(errno));
        return false;
    }

    return valid && apply_profile(selected);
}

static bool load_rules_file(const char *path, bool required) {
    FILE *f = fopen(path, "r");
    if (!f) {
        if (required) {
            fprintf(stderr, "failed to open config %s: %s\n", path, strerror(errno));
            return false;
        }
        return true;
    }

    if (!select_profile_from_file(f, path)) {
        fclose(f);
        return false;
    }

    char line[512];
    unsigned int line_no = 0;
    bool valid = true;
    while (fgets(line, sizeof(line), f)) {
        line_no++;
        char *entry = trim(line);
        if (entry[0] == '\0' || entry[0] == '#') {
            continue;
        }

        char *eq = strchr(entry, '=');
        if (!eq) {
            fprintf(stderr, "invalid config line %u in %s\n", line_no, path);
            valid = false;
            continue;
        }
        *eq = '\0';
        char *key = trim(entry);
        char *value = trim(eq + 1);
        if (strcmp(key, "profile") == 0) {
            continue;
        }
        if (value[0] == '\0') {
            continue;
        }

        if (strcmp(key, "suspicious_exec_exact") == 0) {
            enum edr_severity severity;
            char *rule_value = NULL;
            const char *rule_id = NULL;
            if (!split_rule_value(value, EDR_SEV_WARN, "exec.suspicious_exact",
                                  &rule_value, &severity, &rule_id)) {
                fprintf(stderr, "invalid suspicious_exec_exact on line %u in %s\n", line_no, path);
                valid = false;
                continue;
            }
            if (!add_rule_value(rules.suspicious_exec_exact, rules.suspicious_exec_exact_severity,
                                rules.suspicious_exec_exact_rule_ids,
                                &rules.suspicious_exec_exact_count, MAX_RULES,
                                rule_value, severity, rule_id)) {
                fprintf(stderr, "too many suspicious_exec_exact rules on line %u in %s\n", line_no, path);
                valid = false;
            }
        } else if (strcmp(key, "disable_suspicious_exec_exact") == 0) {
            remove_rule_value(rules.suspicious_exec_exact, rules.suspicious_exec_exact_severity,
                              rules.suspicious_exec_exact_rule_ids,
                              &rules.suspicious_exec_exact_count, value);
        } else if (strcmp(key, "suspicious_exec_prefix") == 0) {
            enum edr_severity severity;
            char *rule_value = NULL;
            const char *rule_id = NULL;
            if (!split_rule_value(value, EDR_SEV_WARN, "exec.suspicious_prefix",
                                  &rule_value, &severity, &rule_id)) {
                fprintf(stderr, "invalid suspicious_exec_prefix on line %u in %s\n", line_no, path);
                valid = false;
                continue;
            }
            if (!add_rule_value(rules.suspicious_exec_prefix, rules.suspicious_exec_prefix_severity,
                                rules.suspicious_exec_prefix_rule_ids,
                                &rules.suspicious_exec_prefix_count, MAX_RULES,
                                rule_value, severity, rule_id)) {
                fprintf(stderr, "too many suspicious_exec_prefix rules on line %u in %s\n", line_no, path);
                valid = false;
            }
        } else if (strcmp(key, "disable_suspicious_exec_prefix") == 0) {
            remove_rule_value(rules.suspicious_exec_prefix, rules.suspicious_exec_prefix_severity,
                              rules.suspicious_exec_prefix_rule_ids,
                              &rules.suspicious_exec_prefix_count, value);
        } else if (strcmp(key, "sensitive_read") == 0) {
            enum edr_severity severity;
            char *rule_value = NULL;
            const char *rule_id = NULL;
            if (!split_rule_value(value, EDR_SEV_WARN, "file.sensitive_read",
                                  &rule_value, &severity, &rule_id)) {
                fprintf(stderr, "invalid sensitive_read on line %u in %s\n", line_no, path);
                valid = false;
                continue;
            }
            if (!add_path_rule(rules.sensitive_read, rules.sensitive_read_severity,
                               rules.sensitive_read_rule_ids, &rules.sensitive_read_count,
                               MAX_RULES, rule_value, severity, rule_id)) {
                fprintf(stderr, "too many sensitive_read rules on line %u in %s\n", line_no, path);
                valid = false;
            }
        } else if (strcmp(key, "disable_sensitive_read") == 0) {
            remove_path_rule(rules.sensitive_read, rules.sensitive_read_severity,
                             rules.sensitive_read_rule_ids, &rules.sensitive_read_count, value);
        } else if (strcmp(key, "sensitive_write") == 0) {
            enum edr_severity severity;
            char *rule_value = NULL;
            const char *rule_id = NULL;
            if (!split_rule_value(value, EDR_SEV_CRITICAL, "file.sensitive_write",
                                  &rule_value, &severity, &rule_id)) {
                fprintf(stderr, "invalid sensitive_write on line %u in %s\n", line_no, path);
                valid = false;
                continue;
            }
            if (!add_path_rule(rules.sensitive_write, rules.sensitive_write_severity,
                               rules.sensitive_write_rule_ids, &rules.sensitive_write_count,
                               MAX_RULES, rule_value, severity, rule_id)) {
                fprintf(stderr, "too many sensitive_write rules on line %u in %s\n", line_no, path);
                valid = false;
            }
        } else if (strcmp(key, "disable_sensitive_write") == 0) {
            remove_path_rule(rules.sensitive_write, rules.sensitive_write_severity,
                             rules.sensitive_write_rule_ids, &rules.sensitive_write_count, value);
        } else if (strcmp(key, "jit_allow_comm") == 0) {
            if (!add_comm_rule(rules.jit_allow_comm, &rules.jit_allow_comm_count, MAX_RULES, value)) {
                fprintf(stderr, "too many jit_allow_comm rules on line %u in %s\n", line_no, path);
                valid = false;
            }
        } else if (strcmp(key, "disable_jit_allow_comm") == 0) {
            remove_comm_rule(rules.jit_allow_comm, &rules.jit_allow_comm_count, value);
        } else if (strcmp(key, "suspicious_port") == 0) {
            enum edr_severity severity;
            char *rule_value = NULL;
            const char *rule_id = NULL;
            if (!split_rule_value(value, EDR_SEV_WARN, "net.suspicious_port",
                                  &rule_value, &severity, &rule_id) ||
                !add_port_rule(rules.suspicious_ports, rules.suspicious_port_severity,
                               rules.suspicious_port_rule_ids, &rules.suspicious_port_count,
                               MAX_RULES, rule_value, severity, rule_id)) {
                fprintf(stderr, "invalid suspicious_port '%s' on line %u in %s\n", value, line_no, path);
                valid = false;
            }
        } else if (strcmp(key, "disable_suspicious_port") == 0) {
            if (!remove_port_rule(rules.suspicious_ports, rules.suspicious_port_severity,
                                  rules.suspicious_port_rule_ids,
                                  &rules.suspicious_port_count, value)) {
                fprintf(stderr, "invalid disable_suspicious_port '%s' on line %u in %s\n", value, line_no, path);
                valid = false;
            }
        } else if (strcmp(key, "flow_allow_transfer") == 0) {
            if (!add_target_rule(rules.flow_allow_transfer, &rules.flow_allow_transfer_count,
                                 MAX_RULES, value)) {
                fprintf(stderr, "too many flow_allow_transfer rules on line %u in %s\n", line_no, path);
                valid = false;
            }
        } else if (strcmp(key, "disable_flow_allow_transfer") == 0) {
            remove_target_rule(rules.flow_allow_transfer, &rules.flow_allow_transfer_count, value);
        } else if (strcmp(key, "disable_rule_id") == 0) {
            if (!valid_rule_id(value) || !add_disabled_rule_id(value)) {
                fprintf(stderr, "invalid disable_rule_id '%s' on line %u in %s\n", value, line_no, path);
                valid = false;
            }
        } else if (strcmp(key, "rule_severity") == 0) {
            enum edr_severity severity = EDR_SEV_WARN;
            const char *rule_id = NULL;
            if (!parse_rule_severity_control(value, &rule_id, &severity) ||
                !add_rule_severity_override(rule_id, severity)) {
                fprintf(stderr, "invalid rule_severity on line %u in %s\n", line_no, path);
                valid = false;
            }
        } else if (strcmp(key, "dedup_window_seconds") == 0) {
            uint64_t seconds = 0;
            if (!parse_u64(value, &seconds) || seconds > UINT64_MAX / NS_PER_SECOND) {
                fprintf(stderr, "invalid dedup_window_seconds '%s' on line %u in %s\n", value, line_no, path);
                valid = false;
                continue;
            }
            rules.dedup_window_ns = seconds * NS_PER_SECOND;
        } else if (strcmp(key, "min_severity") == 0) {
            enum edr_severity severity = EDR_SEV_WARN;
            if (!parse_severity(value, &severity)) {
                fprintf(stderr, "invalid min_severity '%s' on line %u in %s\n", value, line_no, path);
                valid = false;
                continue;
            }
            rules.min_severity = severity;
        } else {
            fprintf(stderr, "unknown config key '%s' on line %u in %s\n", key, line_no, path);
            valid = false;
        }
    }

    fclose(f);
    return valid && validate_rule_id_controls(path);
}

static void strip_newline(char *value) {
    value[strcspn(value, "\r\n")] = '\0';
}

static void read_proc_link(uint32_t pid, const char *name, char *dst, size_t dst_size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/%s", pid, name);

    ssize_t n = readlink(path, dst, dst_size - 1);
    if (n < 0) {
        dst[0] = '\0';
        return;
    }
    dst[n] = '\0';
}

static bool has_deleted_suffix(const char *path) {
    size_t len = strlen(path);
    const char suffix[] = " (deleted)";
    size_t suffix_len = sizeof(suffix) - 1;

    return len >= suffix_len && strcmp(path + len - suffix_len, suffix) == 0;
}

static bool has_path_prefix(const char *path, const char *prefix) {
    return strncmp(path, prefix, strlen(prefix)) == 0;
}

static bool is_writable_exe_path(const char *path) {
    return has_path_prefix(path, "/tmp/") ||
           has_path_prefix(path, "/var/tmp/") ||
           has_path_prefix(path, "/dev/shm/") ||
           has_path_prefix(path, "/home/");
}

static void read_proc_exe_metadata(uint32_t pid, struct process_context *proc) {
    char path[64];
    struct stat st;

    snprintf(path, sizeof(path), "/proc/%u/exe", pid);
    if (stat(path, &st) != 0) {
        return;
    }

    proc->exe_dev = (unsigned long long)st.st_dev;
    proc->exe_inode = (unsigned long long)st.st_ino;
    proc->exe_mode = (unsigned int)st.st_mode;
    proc->exe_uid = (unsigned int)st.st_uid;
    proc->exe_gid = (unsigned int)st.st_gid;
    proc->exe_mtime = (long long)st.st_mtime;
}

static void read_proc_comm(uint32_t pid, char *dst, size_t dst_size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/comm", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        dst[0] = '\0';
        return;
    }

    if (!fgets(dst, dst_size, f)) {
        dst[0] = '\0';
    }
    strip_newline(dst);
    fclose(f);
}

static uint32_t read_proc_ppid(uint32_t pid) {
    char path[64];
    char line[256];
    snprintf(path, sizeof(path), "/proc/%u/status", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }

    uint32_t ppid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "PPid:\t%u", &ppid) == 1) {
            break;
        }
    }
    fclose(f);
    return ppid;
}

static bool read_proc_tty_nr(uint32_t pid, int *tty_nr) {
    char path[64];
    char line[1024];
    snprintf(path, sizeof(path), "/proc/%u/stat", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        return false;
    }

    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return false;
    }
    fclose(f);

    char *comm_end = strrchr(line, ')');
    if (!comm_end) {
        return false;
    }

    char state = '\0';
    unsigned int ppid = 0;
    unsigned int pgrp = 0;
    unsigned int session = 0;
    int parsed_tty_nr = 0;
    if (sscanf(comm_end + 1, " %c %u %u %u %d",
               &state, &ppid, &pgrp, &session, &parsed_tty_nr) != 5) {
        return false;
    }

    (void)state;
    (void)ppid;
    (void)pgrp;
    (void)session;
    *tty_nr = parsed_tty_nr;
    return true;
}

static bool fd_link_is_tty(uint32_t pid, int fd) {
    char path[64];
    char target[EDR_MAX_TARGET];
    snprintf(path, sizeof(path), "/proc/%u/fd/%d", pid, fd);

    ssize_t n = readlink(path, target, sizeof(target) - 1);
    if (n < 0) {
        return false;
    }
    target[n] = '\0';

    return has_path_prefix(target, "/dev/tty") ||
           has_path_prefix(target, "/dev/pts/") ||
           strcmp(target, "/dev/console") == 0;
}

static bool process_has_tty(uint32_t pid) {
    int tty_nr = 0;
    if (read_proc_tty_nr(pid, &tty_nr) && tty_nr > 0) {
        return true;
    }

    return fd_link_is_tty(pid, 0) ||
           fd_link_is_tty(pid, 1) ||
           fd_link_is_tty(pid, 2);
}

static void read_proc_cmdline(uint32_t pid, char *dst, size_t dst_size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);

    FILE *f = fopen(path, "rb");
    if (!f) {
        dst[0] = '\0';
        return;
    }

    size_t n = fread(dst, 1, dst_size - 1, f);
    fclose(f);
    if (n == 0) {
        dst[0] = '\0';
        return;
    }

    for (size_t i = 0; i < n; i++) {
        if (dst[i] == '\0') {
            dst[i] = ' ';
        }
    }
    while (n > 0 && dst[n - 1] == ' ') {
        n--;
    }
    dst[n] = '\0';
}

static void enrich_process(uint32_t pid, struct process_context *proc) {
    memset(proc, 0, sizeof(*proc));
    proc->ppid = read_proc_ppid(pid);
    proc->gppid = read_proc_ppid(proc->ppid);
    read_proc_comm(proc->ppid, proc->parent_comm, sizeof(proc->parent_comm));
    read_proc_comm(proc->gppid, proc->grandparent_comm, sizeof(proc->grandparent_comm));
    proc->has_tty = process_has_tty(pid);
    proc->interactive_session = proc->has_tty;
    read_proc_link(pid, "exe", proc->exe, sizeof(proc->exe));
    proc->exe_deleted = has_deleted_suffix(proc->exe);
    proc->exe_writable_path = is_writable_exe_path(proc->exe);
    read_proc_exe_metadata(pid, proc);
    read_proc_link(pid, "cwd", proc->cwd, sizeof(proc->cwd));
    read_proc_cmdline(pid, proc->cmdline, sizeof(proc->cmdline));
}

static const char *event_name(uint32_t type) {
    switch (type) {
    case EDR_EVENT_EXEC:
        return "EXEC";
    case EDR_EVENT_MPROTECT:
        return "MPROTECT";
    case EDR_EVENT_MMAP:
        return "MMAP";
    case EDR_EVENT_OPENAT:
        return "OPENAT";
    case EDR_EVENT_CONNECT:
        return "CONNECT";
    default:
        return "UNKNOWN";
    }
}

static bool contains_rule(const char *haystack, char ruleset[][EDR_MAX_TARGET],
                          enum edr_severity severities[], char rule_ids[][MAX_RULE_ID],
                          size_t rule_count, enum edr_severity *severity,
                          const char **rule_id) {
    for (size_t i = rule_count; i > 0; i--) {
        size_t idx = i - 1;
        if (strstr(haystack, ruleset[idx]) != NULL) {
            if (rule_controls_allow(rule_ids[idx], severities[idx], severity)) {
                *rule_id = rule_ids[idx];
                return true;
            }
        }
    }
    return false;
}

static bool comm_allowed_for_jit(const char *comm) {
    for (size_t i = 0; i < rules.jit_allow_comm_count; i++) {
        if (strncmp(comm, rules.jit_allow_comm[i], sizeof(rules.jit_allow_comm[i])) == 0) {
            return true;
        }
    }
    return false;
}

static const char *basename_ptr(const char *path) {
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

static bool is_suspicious_exec(const char *target, enum edr_severity *severity,
                               const char **rule_id) {
    const char *base = basename_ptr(target);
    for (size_t i = rules.suspicious_exec_exact_count; i > 0; i--) {
        size_t idx = i - 1;
        if (strcmp(base, rules.suspicious_exec_exact[idx]) == 0) {
            if (rule_controls_allow(rules.suspicious_exec_exact_rule_ids[idx],
                                    rules.suspicious_exec_exact_severity[idx], severity)) {
                *rule_id = rules.suspicious_exec_exact_rule_ids[idx];
                return true;
            }
        }
    }
    for (size_t i = rules.suspicious_exec_prefix_count; i > 0; i--) {
        size_t idx = i - 1;
        if (strncmp(base, rules.suspicious_exec_prefix[idx], strlen(rules.suspicious_exec_prefix[idx])) == 0) {
            if (rule_controls_allow(rules.suspicious_exec_prefix_rule_ids[idx],
                                    rules.suspicious_exec_prefix_severity[idx], severity)) {
                *rule_id = rules.suspicious_exec_prefix_rule_ids[idx];
                return true;
            }
        }
    }

    return false;
}

static bool is_sensitive_read_file(const char *target, enum edr_severity *severity,
                                   const char **rule_id) {
    return contains_rule(target, rules.sensitive_read, rules.sensitive_read_severity,
                         rules.sensitive_read_rule_ids, rules.sensitive_read_count,
                         severity, rule_id);
}

static bool is_sensitive_write_file(const char *target, enum edr_severity *severity,
                                    const char **rule_id) {
    return contains_rule(target, rules.sensitive_write, rules.sensitive_write_severity,
                         rules.sensitive_write_rule_ids, rules.sensitive_write_count,
                         severity, rule_id);
}

static bool opens_for_write(uint32_t flags) {
    int access_mode = flags & O_ACCMODE;
    return access_mode == O_WRONLY || access_mode == O_RDWR || (flags & O_TRUNC) || (flags & O_CREAT);
}

static uint16_t event_dst_port(const struct edr_event *e) {
    return ntohs(e->net_port);
}

struct net_classification {
    const char *scope;
    bool is_private;
    bool is_loopback;
};

static const char *classify_ipv4_addr(uint32_t addr_be, bool *is_private,
                                      bool *is_loopback) {
    uint32_t addr = ntohl(addr_be);
    uint8_t first = (uint8_t)(addr >> 24);
    uint8_t second = (uint8_t)(addr >> 16);

    *is_private = first == 10 ||
                  (first == 172 && second >= 16 && second <= 31) ||
                  (first == 192 && second == 168);
    *is_loopback = first == 127;

    if (first == 0) {
        return "unspecified";
    }
    if (*is_loopback) {
        return "loopback";
    }
    if (*is_private) {
        return "private";
    }
    if (first == 169 && second == 254) {
        return "link-local";
    }
    if (first >= 224 && first <= 239) {
        return "multicast";
    }

    return "public";
}

static bool ipv6_is_unspecified(const uint8_t addr[16]) {
    for (size_t i = 0; i < 16; i++) {
        if (addr[i] != 0) {
            return false;
        }
    }
    return true;
}

static bool ipv6_is_loopback(const uint8_t addr[16]) {
    for (size_t i = 0; i < 15; i++) {
        if (addr[i] != 0) {
            return false;
        }
    }
    return addr[15] == 1;
}

static bool ipv6_is_v4_mapped(const uint8_t addr[16], uint32_t *v4_addr) {
    static const uint8_t prefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
    };

    if (memcmp(addr, prefix, sizeof(prefix)) != 0) {
        return false;
    }

    memcpy(v4_addr, &addr[12], sizeof(*v4_addr));
    return true;
}

static struct net_classification classify_net_destination(const struct edr_event *e) {
    struct net_classification classification = {
        .scope = "",
        .is_private = false,
        .is_loopback = false,
    };

    if (e->net_family == AF_INET) {
        classification.scope = classify_ipv4_addr(e->net_addr_v4,
                                                  &classification.is_private,
                                                  &classification.is_loopback);
    } else if (e->net_family == AF_INET6) {
        uint32_t mapped_v4 = 0;

        if (ipv6_is_v4_mapped(e->net_addr_v6, &mapped_v4)) {
            classification.scope = classify_ipv4_addr(mapped_v4,
                                                      &classification.is_private,
                                                      &classification.is_loopback);
        } else if (ipv6_is_unspecified(e->net_addr_v6)) {
            classification.scope = "unspecified";
        } else if (ipv6_is_loopback(e->net_addr_v6)) {
            classification.scope = "loopback";
            classification.is_loopback = true;
        } else if ((e->net_addr_v6[0] & 0xfe) == 0xfc) {
            classification.scope = "private";
            classification.is_private = true;
        } else if (e->net_addr_v6[0] == 0xfe && (e->net_addr_v6[1] & 0xc0) == 0x80) {
            classification.scope = "link-local";
        } else if (e->net_addr_v6[0] == 0xff) {
            classification.scope = "multicast";
        } else {
            classification.scope = "public";
        }
    }

    return classification;
}

static uint32_t flow_root_pid(const struct edr_event *e, const struct process_context *proc) {
    if (proc->gppid != 0) {
        return proc->gppid;
    }
    if (proc->ppid != 0) {
        return proc->ppid;
    }
    return e->pid;
}

static bool comm_in_list(const char *comm, const char *const values[], size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(comm, values[i]) == 0) {
            return true;
        }
    }
    return false;
}

static const char *path_basename(const char *value) {
    const char *slash = strrchr(value, '/');
    return slash ? slash + 1 : value;
}

static bool command_name_in_list(const char *comm, const char *target,
                                 const char *const values[], size_t count) {
    if (comm_in_list(comm, values, count)) {
        return true;
    }
    if (target && target[0] != '\0' && comm_in_list(path_basename(target), values, count)) {
        return true;
    }
    return false;
}

static bool is_shell_command(const char *comm, const char *target) {
    static const char *const shells[] = {
        "sh", "bash", "dash", "zsh",
    };
    return command_name_in_list(comm, target, shells, sizeof(shells) / sizeof(shells[0]));
}

static bool is_transfer_command(const char *comm, const char *target) {
    static const char *const transfer_tools[] = {
        "curl", "wget", "nc", "ncat", "socat", "scp", "rsync", "rclone",
        "busybox", "python", "python3", "perl",
    };
    return command_name_in_list(comm, target, transfer_tools,
                                sizeof(transfer_tools) / sizeof(transfer_tools[0]));
}

static bool flow_transfer_allowlisted(const struct edr_event *e,
                                      const struct process_context *proc) {
    for (size_t i = rules.flow_allow_transfer_count; i > 0; i--) {
        const char *value = rules.flow_allow_transfer[i - 1];
        if ((e->comm[0] != '\0' && strcmp(e->comm, value) == 0) ||
            (e->target[0] != '\0' && strcmp(e->target, value) == 0) ||
            (proc->exe[0] != '\0' && strcmp(proc->exe, value) == 0)) {
            return true;
        }
    }
    return false;
}

static bool process_tree_has_shell_context(const struct edr_event *e,
                                           const struct process_context *proc) {
    return is_shell_command(e->comm, e->target) ||
           is_shell_command(proc->parent_comm, NULL) ||
           is_shell_command(proc->grandparent_comm, NULL);
}

static bool flow_entry_expired(const struct flow_state_entry *entry, uint64_t now_ns) {
    return entry->active &&
           (now_ns < entry->last_seen_ns ||
            now_ns - entry->last_seen_ns > (uint64_t)FLOW_WINDOW_SECONDS * NS_PER_SECOND);
}

static struct flow_state_entry *flow_state_get(uint32_t root_pid, uint64_t now_ns) {
    struct flow_state_entry *free_entry = NULL;

    for (size_t i = 0; i < FLOW_STATE_ENTRIES; i++) {
        struct flow_state_entry *entry = &flow_state[i];
        if (flow_entry_expired(entry, now_ns)) {
            memset(entry, 0, sizeof(*entry));
        }
        if (entry->active && entry->root_pid == root_pid) {
            return entry;
        }
        if (!entry->active && !free_entry) {
            free_entry = entry;
        }
    }

    if (!free_entry) {
        free_entry = &flow_state[flow_state_cursor++ % FLOW_STATE_ENTRIES];
    }

    memset(free_entry, 0, sizeof(*free_entry));
    free_entry->active = true;
    free_entry->root_pid = root_pid;
    free_entry->last_seen_ns = now_ns;
    return free_entry;
}

static void flow_state_observe_event(const struct edr_event *e,
                                     const struct process_context *proc) {
    if (e->type != EDR_EVENT_EXEC && e->type != EDR_EVENT_CONNECT) {
        return;
    }

    struct flow_state_entry *entry = flow_state_get(flow_root_pid(e, proc), e->timestamp_ns);
    entry->last_seen_ns = e->timestamp_ns;

    if (e->type == EDR_EVENT_EXEC) {
        if (is_shell_command(e->comm, e->target)) {
            entry->shell_seen = true;
            entry->shell_pid = e->pid;
        }
        if (is_transfer_command(e->comm, e->target)) {
            entry->transfer_exec_seen = true;
            entry->transfer_pid = e->pid;
        }
        return;
    }

    if (strcmp(classify_net_destination(e).scope, "public") == 0) {
        entry->public_connect_seen = true;
    }
}

static void flow_state_observe_sensitive_read(const struct edr_event *e,
                                              const struct process_context *proc) {
    struct flow_state_entry *entry = flow_state_get(flow_root_pid(e, proc), e->timestamp_ns);
    entry->last_seen_ns = e->timestamp_ns;
    entry->sensitive_read_seen = true;
    entry->sensitive_read_pid = e->pid;
}

static const struct flow_state_entry *flow_state_lookup(uint32_t root_pid, uint64_t now_ns) {
    for (size_t i = 0; i < FLOW_STATE_ENTRIES; i++) {
        struct flow_state_entry *entry = &flow_state[i];
        if (flow_entry_expired(entry, now_ns)) {
            memset(entry, 0, sizeof(*entry));
            continue;
        }
        if (entry->active && entry->root_pid == root_pid) {
            return entry;
        }
    }
    return NULL;
}

static bool make_controlled_flow_finding(enum edr_severity default_severity,
                                         const char *rule_id,
                                         const char *reason,
                                         uint32_t score,
                                         const char *flow_reasons,
                                         uint32_t flow_root,
                                         struct edr_finding *finding) {
    if (!make_controlled_finding(default_severity, rule_id, reason, finding)) {
        return false;
    }

    finding->has_flow = true;
    finding->flow_id = rule_id;
    finding->flow_score = score;
    finding->flow_reasons = flow_reasons;
    finding->flow_window_seconds = FLOW_WINDOW_SECONDS;
    finding->flow_root_pid = flow_root;
    return true;
}

static bool evaluate_connect_flow(const struct edr_event *e,
                                  const struct process_context *proc,
                                  struct edr_finding *finding) {
    if (e->type != EDR_EVENT_CONNECT ||
        strcmp(classify_net_destination(e).scope, "public") != 0 ||
        !is_transfer_command(e->comm, e->target)) {
        return false;
    }

    uint32_t root_pid = flow_root_pid(e, proc);
    const struct flow_state_entry *entry = flow_state_lookup(root_pid, e->timestamp_ns);
    bool shell_context = process_tree_has_shell_context(e, proc) ||
                         (entry && entry->shell_seen);
    bool sensitive_read_context = entry && entry->sensitive_read_seen;

    if (sensitive_read_context) {
        bool suspicious_context = shell_context || !proc->has_tty;
        uint32_t score = default_flow_rule_score(FLOW_RULE_SENSITIVE_READ_THEN_PUBLIC_NET,
                                                 suspicious_context);
        const char *reasons = "sensitive_read,transfer_tool,public_destination";
        if (suspicious_context) {
            reasons = "sensitive_read,transfer_tool,public_destination,suspicious_context";
        }
        if (make_controlled_flow_finding(
                default_flow_rule_severity(FLOW_RULE_SENSITIVE_READ_THEN_PUBLIC_NET),
                FLOW_RULE_SENSITIVE_READ_THEN_PUBLIC_NET,
                "sensitive file access followed by public network transfer",
                score,
                reasons,
                root_pid,
                finding)) {
            return true;
        }
    }

    if (shell_context) {
        if (make_controlled_flow_finding(
                default_flow_rule_severity(FLOW_RULE_SHELL_DOWNLOADER_PUBLIC_NET),
                FLOW_RULE_SHELL_DOWNLOADER_PUBLIC_NET,
                "shell-launched transfer tool connected to public network",
                default_flow_rule_score(FLOW_RULE_SHELL_DOWNLOADER_PUBLIC_NET, false),
                "shell_context,transfer_tool,public_destination",
                root_pid,
                finding)) {
            return true;
        }
    }

    if (!proc->has_tty) {
        bool allowlisted = flow_transfer_allowlisted(e, proc);
        return make_controlled_flow_finding(
            allowlisted ? EDR_SEV_INFO :
                default_flow_rule_severity(FLOW_RULE_NO_TTY_PUBLIC_TRANSFER_TOOL),
            FLOW_RULE_NO_TTY_PUBLIC_TRANSFER_TOOL,
            "transfer tool without TTY connected to public network",
            allowlisted ? 20U :
                default_flow_rule_score(FLOW_RULE_NO_TTY_PUBLIC_TRANSFER_TOOL, false),
            allowlisted ? "no_tty,transfer_tool,public_destination,flow_allow_transfer" :
                "no_tty,transfer_tool,public_destination",
            root_pid,
            finding);
    }

    return false;
}

static bool is_suspicious_port(uint16_t port, enum edr_severity *severity,
                               const char **rule_id) {
    for (size_t i = rules.suspicious_port_count; i > 0; i--) {
        size_t idx = i - 1;
        if (rules.suspicious_ports[idx] == port) {
            if (rule_controls_allow(rules.suspicious_port_rule_ids[idx],
                                    rules.suspicious_port_severity[idx], severity)) {
                *rule_id = rules.suspicious_port_rule_ids[idx];
                return true;
            }
        }
    }
    return false;
}

static void format_net_addr(const struct edr_event *e, char *dst, size_t dst_size) {
    if (e->net_family == AF_INET) {
        struct in_addr addr = {
            .s_addr = e->net_addr_v4,
        };
        if (inet_ntop(AF_INET, &addr, dst, dst_size)) {
            return;
        }
    } else if (e->net_family == AF_INET6) {
        if (inet_ntop(AF_INET6, e->net_addr_v6, dst, dst_size)) {
            return;
        }
    }

    if (dst_size > 0) {
        dst[0] = '\0';
    }
}

static struct edr_finding make_finding(enum edr_severity severity, const char *rule_id,
                                       const char *reason) {
    return (struct edr_finding){
        .severity = severity,
        .rule_id = rule_id,
        .reason = reason,
    };
}

static bool make_controlled_finding(enum edr_severity default_severity, const char *rule_id,
                                    const char *reason, struct edr_finding *finding) {
    enum edr_severity severity = default_severity;
    if (!rule_controls_allow(rule_id, default_severity, &severity)) {
        return false;
    }
    *finding = make_finding(severity, rule_id, reason);
    return true;
}

static struct edr_finding evaluate_event(const struct edr_event *e,
                                         const struct process_context *proc) {
    enum edr_severity severity = EDR_SEV_INFO;
    const char *rule_id = NULL;
    struct edr_finding finding;

    if (e->type == EDR_EVENT_EXEC && is_suspicious_exec(e->target, &severity, &rule_id)) {
        return make_finding(severity, rule_id, "suspicious process execution");
    }

    if (e->type == EDR_EVENT_MPROTECT && (e->prot & PROT_EXEC) && !comm_allowed_for_jit(e->comm)) {
        if (e->prot & PROT_WRITE) {
            if (make_controlled_finding(EDR_SEV_CRITICAL, "mem.rwx_mprotect",
                                        "RWX memory request", &finding)) {
                return finding;
            }
            return make_finding(EDR_SEV_INFO, "event.observed", "observed");
        }
        if (make_controlled_finding(EDR_SEV_WARN, "mem.exec_mprotect",
                                    "mprotect executable memory request", &finding)) {
            return finding;
        }
        return make_finding(EDR_SEV_INFO, "event.observed", "observed");
    }

    if (e->type == EDR_EVENT_MMAP && (e->prot & PROT_EXEC) && !comm_allowed_for_jit(e->comm)) {
        if (e->prot & PROT_WRITE) {
            if (make_controlled_finding(EDR_SEV_CRITICAL, "mem.rwx_mmap",
                                        "RWX memory mapping", &finding)) {
                return finding;
            }
            return make_finding(EDR_SEV_INFO, "event.observed", "observed");
        }
        if (e->flags & MAP_ANONYMOUS) {
            if (make_controlled_finding(rules.anon_exec_mmap_severity, "mem.anon_exec_mmap",
                                        "anonymous executable memory mapping", &finding)) {
                return finding;
            }
            return make_finding(EDR_SEV_INFO, "event.observed", "observed");
        }
    }

    if (e->type == EDR_EVENT_OPENAT) {
        if (opens_for_write(e->flags) && is_sensitive_write_file(e->target, &severity, &rule_id)) {
            return make_finding(severity, rule_id, "sensitive file opened for write");
        }
        if (is_sensitive_read_file(e->target, &severity, &rule_id)) {
            return make_finding(severity, rule_id, "sensitive file access");
        }
    }

    if (evaluate_connect_flow(e, proc, &finding)) {
        return finding;
    }

    if (e->type == EDR_EVENT_CONNECT && is_suspicious_port(event_dst_port(e), &severity, &rule_id)) {
        return make_finding(severity, rule_id, "connection to suspicious port");
    }

    return make_finding(EDR_SEV_INFO, "event.observed", "observed");
}

static void format_event(const struct edr_event *e, const struct process_context *proc,
                         char *line, size_t line_size) {
    if (e->type == EDR_EVENT_EXEC) {
        snprintf(line, line_size,
                 "pid=%u ppid=%u parent=%s gppid=%u grandparent=%s uid=%u comm=%s event=exec target=%.120s exe=%.120s",
                 e->pid, proc->ppid, proc->parent_comm, proc->gppid, proc->grandparent_comm,
                 e->uid, e->comm, e->target, proc->exe);
    } else if (e->type == EDR_EVENT_MPROTECT || e->type == EDR_EVENT_MMAP) {
        snprintf(line, line_size,
                 "pid=%u ppid=%u parent=%s gppid=%u grandparent=%s uid=%u comm=%s event=%s prot=0x%x flags=0x%x exe=%.120s",
                 e->pid, proc->ppid, proc->parent_comm, proc->gppid, proc->grandparent_comm,
                 e->uid, e->comm,
                 event_name(e->type), e->prot, e->flags, proc->exe);
    } else if (e->type == EDR_EVENT_OPENAT) {
        snprintf(line, line_size,
                 "pid=%u ppid=%u parent=%s gppid=%u grandparent=%s uid=%u comm=%s event=openat flags=0x%x target=%.120s exe=%.120s",
                 e->pid, proc->ppid, proc->parent_comm, proc->gppid, proc->grandparent_comm,
                 e->uid, e->comm,
                 e->flags, e->target, proc->exe);
    } else if (e->type == EDR_EVENT_CONNECT) {
        char addr[INET6_ADDRSTRLEN] = "";
        format_net_addr(e, addr, sizeof(addr));
        snprintf(line, line_size,
                 "pid=%u ppid=%u parent=%s gppid=%u grandparent=%s uid=%u comm=%s event=connect dst=%s:%u exe=%.120s",
                 e->pid, proc->ppid, proc->parent_comm, proc->gppid, proc->grandparent_comm,
                 e->uid, e->comm,
                 addr, event_dst_port(e), proc->exe);
    } else {
        snprintf(line, line_size,
                 "pid=%u ppid=%u parent=%s gppid=%u grandparent=%s uid=%u comm=%s event=unknown type=%u",
                 e->pid, proc->ppid, proc->parent_comm, proc->gppid, proc->grandparent_comm,
                 e->uid, e->comm, e->type);
    }
}

static void json_escape(FILE *out, const char *value) {
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\') {
            fputc('\\', out);
            fputc(*p, out);
        } else if (*p >= 0x20 && *p <= 0x7e) {
            fputc(*p, out);
        } else {
            fprintf(out, "\\u%04x", *p);
        }
    }
}

static void write_jsonl(FILE *out, const struct edr_event *e,
                        const struct process_context *proc,
                        const struct edr_finding *finding,
                        uint32_t repeat_count) {
    if (!out) {
        return;
    }

    fprintf(out, "{\"record\":\"finding\",");
    write_jsonl_metadata(out, rules.profile_name);
    fprintf(out,
            ",\"timestamp_ns\":%llu,\"event\":\"%s\",\"pid\":%u,\"tid\":%u,"
            "\"ppid\":%u,\"gppid\":%u,\"uid\":%u,\"gid\":%u,\"comm\":\"",
            (unsigned long long)e->timestamp_ns, event_name(e->type), e->pid, e->tid,
            proc->ppid, proc->gppid, e->uid, e->gid);
    json_escape(out, e->comm);
    fprintf(out, "\",\"parent_comm\":\"");
    json_escape(out, proc->parent_comm);
    fprintf(out, "\",\"grandparent_comm\":\"");
    json_escape(out, proc->grandparent_comm);
    fprintf(out, "\",\"exe\":\"");
    json_escape(out, proc->exe);
    fprintf(out, "\",\"cwd\":\"");
    json_escape(out, proc->cwd);
    fprintf(out, "\",\"cmdline\":\"");
    json_escape(out, proc->cmdline);
    fprintf(out, "\",\"target\":\"");
    json_escape(out, e->target);
    char dst_addr[INET6_ADDRSTRLEN] = "";
    if (e->type == EDR_EVENT_CONNECT) {
        format_net_addr(e, dst_addr, sizeof(dst_addr));
    }
    fprintf(out, "\",\"dst_addr\":\"");
    json_escape(out, dst_addr);
    fprintf(out, "\"");
    if (e->type == EDR_EVENT_CONNECT) {
        struct net_classification dst = classify_net_destination(e);
        fprintf(out, ",\"dst_scope\":\"");
        json_escape(out, dst.scope);
        fprintf(out, "\",\"dst_is_private\":%s,\"dst_is_loopback\":%s",
                dst.is_private ? "true" : "false",
                dst.is_loopback ? "true" : "false");
    }
    fprintf(out,
            ",\"dst_port\":%u,\"prot\":%u,\"flags\":%u,"
            "\"exe_dev\":%llu,\"exe_inode\":%llu,\"exe_mode\":%u,\"exe_uid\":%u,\"exe_gid\":%u,"
            "\"exe_mtime\":%lld,\"exe_deleted\":%s,\"exe_writable_path\":%s,"
            "\"has_tty\":%s,\"interactive_session\":%s,"
            "\"severity\":%d,\"repeat_count\":%u,\"rule_id\":\"",
            e->type == EDR_EVENT_CONNECT ? event_dst_port(e) : 0,
            e->prot, e->flags,
            proc->exe_dev, proc->exe_inode, proc->exe_mode, proc->exe_uid, proc->exe_gid,
            proc->exe_mtime, proc->exe_deleted ? "true" : "false",
            proc->exe_writable_path ? "true" : "false",
            proc->has_tty ? "true" : "false",
            proc->interactive_session ? "true" : "false",
            finding->severity, repeat_count);
    json_escape(out, finding->rule_id);
    fprintf(out, "\",\"reason\":\"");
    json_escape(out, finding->reason);
    if (finding->has_flow) {
        fprintf(out, "\",\"flow_id\":\"");
        json_escape(out, finding->flow_id);
        fprintf(out, "\",\"flow_score\":%u,\"flow_reasons\":\"",
                finding->flow_score);
        json_escape(out, finding->flow_reasons);
        fprintf(out,
                "\",\"flow_window_seconds\":%u,\"flow_root_pid\":%u",
                finding->flow_window_seconds, finding->flow_root_pid);
        fprintf(out, "}\n");
    } else {
        fprintf(out, "\"}\n");
    }
    fflush(out);
}

static bool same_dedup_key(const struct dedup_entry *entry, const struct edr_event *e,
                           const struct edr_finding *finding) {
    return entry->active &&
           entry->type == e->type &&
           entry->pid == e->pid &&
           entry->prot == e->prot &&
           entry->flags == e->flags &&
           entry->net_family == e->net_family &&
           entry->net_port == e->net_port &&
           entry->reason == finding->reason &&
           entry->rule_id == finding->rule_id &&
           entry->has_flow == finding->has_flow &&
           entry->flow_root_pid == finding->flow_root_pid &&
           strncmp(entry->comm, e->comm, sizeof(entry->comm)) == 0 &&
           strncmp(entry->target, e->target, sizeof(entry->target)) == 0;
}

static void emit_finding(struct edr_options *opts, const struct edr_event *e,
                         const struct process_context *proc,
                         const struct edr_finding *finding, uint32_t repeat_count) {
    char line[MAX_EVENT_MESSAGE];

    format_event(e, proc, line, sizeof(line));
    add_traffic(line);

    if (finding->severity > EDR_SEV_INFO) {
        add_alert("EDR", line, finding->severity);
    }

    if (!opts || opts->console) {
        fprintf(stdout, "[EDR%s] %s repeat_count=%u%s%s\n",
                finding->severity > EDR_SEV_INFO ? " ALERT" : "",
                line,
                repeat_count,
                finding->severity > EDR_SEV_INFO ? " reason=" : "",
                finding->severity > EDR_SEV_INFO ? finding->reason : "");
        fflush(stdout);
    }

    if (opts) {
        write_jsonl(opts->jsonl, e, proc, finding, repeat_count);
    }
}

static void clear_dedup_entry(struct dedup_entry *entry) {
    memset(entry, 0, sizeof(*entry));
}

static void emit_dedup_entry(struct edr_options *opts, struct dedup_entry *entry) {
    if (!entry->active || entry->repeat_count == 0) {
        clear_dedup_entry(entry);
        return;
    }

    struct edr_finding finding = {
        .severity = entry->severity,
        .rule_id = entry->rule_id,
        .reason = entry->reason,
        .has_flow = entry->has_flow,
        .flow_id = entry->flow_id,
        .flow_score = entry->flow_score,
        .flow_reasons = entry->flow_reasons,
        .flow_window_seconds = entry->flow_window_seconds,
        .flow_root_pid = entry->flow_root_pid,
    };
    struct process_context proc;
    enrich_process(entry->event.pid, &proc);
    emit_finding(opts, &entry->event, &proc, &finding, entry->repeat_count);
    clear_dedup_entry(entry);
}

static bool suppress_duplicate(struct edr_options *opts, const struct edr_event *e,
                               const struct edr_finding *finding) {
    for (size_t i = 0; i < DEDUP_ENTRIES; i++) {
        struct dedup_entry *entry = &dedup_cache[i];
        if (same_dedup_key(entry, e, finding)) {
            if (rules.dedup_window_ns > 0 && e->timestamp_ns - entry->last_seen_ns < rules.dedup_window_ns) {
                entry->last_seen_ns = e->timestamp_ns;
                entry->repeat_count++;
                return true;
            }
            emit_dedup_entry(opts, entry);
            return false;
        }
    }

    struct dedup_entry *entry = &dedup_cache[dedup_cursor++ % DEDUP_ENTRIES];
    if (entry->active && entry->repeat_count > 0) {
        emit_dedup_entry(opts, entry);
    }
    entry->active = true;
    entry->type = e->type;
    entry->pid = e->pid;
    entry->prot = e->prot;
    entry->flags = e->flags;
    entry->net_family = e->net_family;
    entry->net_port = e->net_port;
    entry->last_seen_ns = e->timestamp_ns;
    entry->repeat_count = 0;
    entry->event = *e;
    entry->reason = finding->reason;
    entry->rule_id = finding->rule_id;
    entry->severity = finding->severity;
    entry->has_flow = finding->has_flow;
    entry->flow_id = finding->flow_id;
    entry->flow_score = finding->flow_score;
    entry->flow_reasons = finding->flow_reasons;
    entry->flow_window_seconds = finding->flow_window_seconds;
    entry->flow_root_pid = finding->flow_root_pid;
    snprintf(entry->comm, sizeof(entry->comm), "%s", e->comm);
    snprintf(entry->target, sizeof(entry->target), "%s", e->target);
    return false;
}

static void flush_dedup_cache(struct edr_options *opts) {
    for (size_t i = 0; i < DEDUP_ENTRIES; i++) {
        emit_dedup_entry(opts, &dedup_cache[i]);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct edr_options *opts = ctx;
    if (data_sz < sizeof(struct edr_event)) {
        return 0;
    }

    struct edr_event *e = data;
    struct process_context proc;
    bool proc_enriched = false;
    memset(&proc, 0, sizeof(proc));

    if (e->type == EDR_EVENT_EXEC || e->type == EDR_EVENT_CONNECT) {
        enrich_process(e->pid, &proc);
        proc_enriched = true;
        flow_state_observe_event(e, &proc);
    }
    struct edr_finding finding = evaluate_event(e, &proc);

    if (e->type == EDR_EVENT_OPENAT &&
        finding.rule_id &&
        rule_id_matches_family(finding.rule_id, "file.sensitive_read")) {
        if (!proc_enriched) {
            enrich_process(e->pid, &proc);
            proc_enriched = true;
        }
        flow_state_observe_sensitive_read(e, &proc);
    }

    if (e->type == EDR_EVENT_EXEC) {
        g_telemetry.exec_events++;
    } else if (e->type == EDR_EVENT_MPROTECT || e->type == EDR_EVENT_MMAP) {
        g_telemetry.mem_events++;
    } else if (e->type == EDR_EVENT_OPENAT) {
        g_telemetry.file_events++;
    } else if (e->type == EDR_EVENT_CONNECT) {
        g_telemetry.net_events++;
    }

    if (finding.severity > EDR_SEV_INFO) {
        g_telemetry.suspicious_events++;
    }

    bool should_emit = (finding.severity > EDR_SEV_INFO && finding.severity >= rules.min_severity) ||
                       (opts && opts->all_events);
    if (opts && !opts->all_events && finding.severity > EDR_SEV_INFO &&
        finding.severity >= rules.min_severity &&
        suppress_duplicate(opts, e, &finding)) {
        should_emit = false;
    }

    if (!should_emit) {
        return 0;
    }

    if (!proc_enriched) {
        enrich_process(e->pid, &proc);
    }
    emit_finding(opts, e, &proc, &finding, 0);
    return 0;
}

static struct bpf_link *attach_tracepoint(struct bpf_object *obj,
                                          const char *prog_name,
                                          const char *category,
                                          const char *name) {
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "missing BPF program: %s\n", prog_name);
        return NULL;
    }

    struct bpf_link *link = bpf_program__attach_tracepoint(prog, category, name);
    if (!link) {
        fprintf(stderr, "failed to attach %s:%s\n", category, name);
    }
    return link;
}

int main(int argc, char **argv) {
    struct edr_options opts = {
        .config_path = DEFAULT_CONFIG_PATH,
        .bpf_path = "asic_sensor.bpf.o",
        .jsonl = NULL,
        .console = true,
        .all_events = false,
        .check_config = false,
    };

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            opts.jsonl = fopen(argv[++i], "a");
            if (!opts.jsonl) {
                fprintf(stderr, "failed to open JSONL output %s: %s\n", argv[i], strerror(errno));
                return 1;
            }
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            opts.console = false;
        } else if (strcmp(argv[i], "--all-events") == 0) {
            opts.all_events = true;
        } else if (strcmp(argv[i], "--check-config") == 0) {
            opts.check_config = true;
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            opts.config_path = argv[++i];
        } else if (strcmp(argv[i], "--bpf") == 0 && i + 1 < argc) {
            opts.bpf_path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            fprintf(stdout, "usage: %s [-c rules.conf] [-o events.jsonl] [--quiet] [--all-events] [--check-config] [--bpf path]\n", argv[0]);
            return 0;
        } else {
            fprintf(stderr, "usage: %s [-c rules.conf] [-o events.jsonl] [--quiet] [--all-events] [--check-config] [--bpf path]\n", argv[0]);
            return 1;
        }
    }

    init_default_rules();
    if (!load_rules_file(opts.config_path, opts.check_config)) {
        if (opts.jsonl) {
            fclose(opts.jsonl);
        }
        return 1;
    }
    init_agent_metadata(opts.config_path);

    if (opts.check_config) {
        struct policy_summary summary = current_policy_summary();
        if (opts.console) {
            write_policy_summary_console(stdout, &summary, "config ok: ");
        }
        if (opts.jsonl) {
            fclose(opts.jsonl);
        }
        return 0;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct bpf_object *obj = bpf_object__open_file(opts.bpf_path, NULL);
    if (!obj) {
        fprintf(stderr, "failed to open %s\n", opts.bpf_path);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load EDR sensor\n");
        bpf_object__close(obj);
        return 1;
    }

    links[0] = attach_tracepoint(obj, "trace_execve", "syscalls", "sys_enter_execve");
    links[1] = attach_tracepoint(obj, "trace_mprotect", "syscalls", "sys_enter_mprotect");
    links[2] = attach_tracepoint(obj, "trace_mmap", "syscalls", "sys_enter_mmap");
    links[3] = attach_tracepoint(obj, "trace_openat", "syscalls", "sys_enter_openat");
    links[4] = attach_tracepoint(obj, "trace_connect", "syscalls", "sys_enter_connect");

    if (!links[0] || !links[1] || !links[2] || !links[3] || !links[4]) {
        for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
            if (links[i]) {
                bpf_link__destroy(links[i]);
            }
        }
        bpf_object__close(obj);
        return 1;
    }

    int rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    if (rb_fd < 0) {
        fprintf(stderr, "failed to find ring buffer map\n");
        for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
            bpf_link__destroy(links[i]);
        }
        bpf_object__close(obj);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_event, &opts, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
            bpf_link__destroy(links[i]);
        }
        bpf_object__close(obj);
        return 1;
    }

    if (opts.console) {
        printf("--- ASIC-SOC EDR %s online ---\n", ASIC_EDR_VERSION);
        struct policy_summary summary = current_policy_summary();
        write_policy_summary_console(stdout, &summary, "policy: ");
    }
    if (opts.jsonl) {
        struct policy_summary summary = current_policy_summary();
        write_policy_summary_jsonl(opts.jsonl, &summary);
    }
    while (!stop) {
        update_telemetry_stats();
        ring_buffer__poll(rb, 250);
    }

    flush_dedup_cache(&opts);
    ring_buffer__free(rb);
    for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
        if (links[i]) {
            bpf_link__destroy(links[i]);
        }
    }
    bpf_object__close(obj);
    if (opts.jsonl) {
        fclose(opts.jsonl);
    }
    return 0;
}
