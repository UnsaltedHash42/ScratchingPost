/* Self-acting behavior demo sample for ScratchingPost (step 1b: prove the sandbox
 * catches malicious *behavior*, not just an unsigned exec).
 *
 * On launch it drops a LaunchAgent plist into ~/Library/LaunchAgents/ — the classic
 * macOS user-persistence primitive (MITRE T1543.001). ScratchingPost's ESF recorder
 * sees the file_create at that path and the custom Wazuh rule 100010 fires. The binary
 * is adhoc-signed, so it also trips 100020 (T1553) on its own exec, but 100010 is the
 * point: a persistence behavior the sample performed, in its own process subtree.
 *
 * Writes directly to the final path with open(O_CREAT) so the ESF event carries the
 * LaunchAgents path (an atomic temp+rename would too — rule 100010 also matches rename).
 * Does NOT load the agent (no launchctl), so nothing persists on the host beyond the
 * disposable clone; the clone is reverted regardless.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static const char *PLIST =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
    "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\"><dict>\n"
    "  <key>Label</key><string>com.scratchingpost.persist</string>\n"
    "  <key>ProgramArguments</key><array><string>/bin/echo</string>"
    "<string>scratchingpost</string></array>\n"
    "  <key>RunAtLoad</key><true/>\n"
    "</dict></plist>\n";

int main(void) {
    const char *home = getenv("HOME");
    if (!home || !*home) home = "/tmp";

    char lib[1100], dir[1200], path[1400];
    snprintf(lib, sizeof(lib), "%s/Library", home);
    snprintf(dir, sizeof(dir), "%s/Library/LaunchAgents", home);
    snprintf(path, sizeof(path), "%s/com.scratchingpost.persist.plist", dir);

    mkdir(lib, 0755);  /* create each level; harmless if already present */
    mkdir(dir, 0755);  /* ~/Library exists on a real guest, but be robust in a bare HOME */

    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return 1; }
    if (write(fd, PLIST, strlen(PLIST)) < 0) { perror("write"); close(fd); return 1; }
    close(fd);

    printf("dropped LaunchAgent: %s\n", path);
    return 0;
}
