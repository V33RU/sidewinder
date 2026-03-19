/*
 * Intentionally vulnerable C code for scanner validation.
 * DO NOT use in production. Every function here is unsafe.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/* wifi_cmd: Command injection via system() */
void handle_ssid_cmd(const char *ssid) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iwconfig wlan0 essid %s", ssid);
    system(cmd);
}

/* wifi_cmd: Command injection via popen() */
void log_ssid_popen(const char *ssid) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "echo %s >> /tmp/wifi.log", ssid);
    popen(cmd, "r");
}

/* wifi_overflow: Buffer overflow via sprintf() */
void store_ssid_overflow(const char *ssid) {
    char buf[64];
    sprintf(buf, "iwpriv ra0 set SSID=%s", ssid);
}

/* wifi_overflow: strcpy without length check */
void copy_ssid(const char *ssid) {
    char local_ssid[32];
    strcpy(local_ssid, ssid);
}

/* wifi_overflow: memcpy with attacker-controlled length */
void parse_ie(const unsigned char *ie_data, int ssid_len) {
    char ssid[32];
    memcpy(ssid, ie_data, ssid_len);
    ssid[ssid_len] = '\0';
}

/* wifi_fmt: Format string - SSID as format argument */
void log_ssid_vulnerable(const char *ssid) {
    syslog(LOG_INFO, ssid);
}

/* wifi_fmt: printf with SSID as format */
void print_ssid_bad(const char *ssid) {
    printf(ssid);
}

/* wifi_esc: Terminal escape - SSID to serial without filtering */
void serial_output(const char *ssid) {
    printf("AP found: %s\n", ssid);
}

/* wifi_serial: SQL injection via SSID */
void save_to_db(const char *ssid) {
    char query[512];
    sprintf(query, "INSERT INTO wifi_history (ssid) VALUES ('%s')", ssid);
    /* sqlite3_exec(db, query, NULL, NULL, NULL); */
}

/* wifi_path: Path traversal via SSID in filename */
void log_to_file(const char *ssid) {
    char path[256];
    snprintf(path, sizeof(path), "/var/log/wifi/%s.log", ssid);
    FILE *f = fopen(path, "a");
    if (f) fclose(f);
}

/* wifi_nosql: LDAP injection via SSID */
void ldap_lookup(const char *ssid) {
    char filter[256];
    sprintf(filter, "(ssid=%s)", ssid);
    /* ldap_search_s(ld, base, LDAP_SCOPE_SUBTREE, filter, ...); */
}

/* wifi_probe: SSID parser with null-termination assumption */
void parse_ssid_ie(const void *ie, int ssid_len) {
    char display_ssid[33];
    strncpy(display_ssid, ie, ssid_len);
    display_ssid[ssid_len] = '\0';
}
