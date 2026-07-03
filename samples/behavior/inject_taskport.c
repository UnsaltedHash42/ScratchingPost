/* Self-acting behavior demo sample for ScratchingPost (step 1a: prove the sandbox
 * catches the macOS *injection* primitive, not just an unsigned exec).
 *
 * On launch it forks a child and acquires the child's Mach task port with
 * task_for_pid() — the surviving macOS process-injection primitive
 * (task_for_pid -> mach_vm_write -> remote thread; MITRE T1055). The kernel emits
 * an ESF get_task event whose acting process is this sample, so ScratchingPost's
 * recorder sees it, subtree scoping keeps it (the event's subject pid is the
 * sample's own), and the custom Wazuh rule 100001 fires. The binary is
 * adhoc-signed, so it also trips 100020 (T1553) on its own exec, but the get_task
 * is the point: an injection behavior the sample performed, in its own subtree.
 *
 * The target is a plain fork() of this process (same uid, adhoc, no hardened
 * runtime), so task_for_pid succeeds without exotic privileges; on the detonation
 * guest (root, SIP disabled) it is unrestricted. The sample also signs itself with
 * get-task-allow (see build.sh), so the acquisition succeeds even off the guest.
 * The child only pause()s to be acquired, is killed immediately, never execs and
 * never touches the host beyond the disposable clone, which is reverted regardless.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>

int main(void) {
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        pause();      /* target: wait to be acquired, then killed by the parent */
        _exit(0);
    }

    usleep(200000);   /* let the child become schedulable before acquiring it */

    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), child, &port);
    if (kr == KERN_SUCCESS) {
        printf("acquired task port for pid %d: port=0x%x\n", child, port);
        mach_port_deallocate(mach_task_self(), port);
    } else {
        fprintf(stderr, "task_for_pid(%d) failed: %s (0x%x)\n",
                child, mach_error_string(kr), kr);
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return kr == KERN_SUCCESS ? 0 : 1;
}
