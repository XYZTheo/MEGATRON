package net.megatron.provisioning

/**
 * Keeps the switch's credentials in step with the customer list: writes the
 * file, then makes sure the switch has actually re-read it.
 *
 * A CHANGED FILE IS NOT A PUBLISHED CREDENTIAL. db_text loads its tables once
 * at startup, so the write is half the job and the reload is the other half.
 * The first version tied the reload to the write — reload only when the
 * content changed — which is right for the happy path and wrong the moment a
 * reload fails:
 *
 *   14:00  /rotate a leaked account
 *          the file is rewritten, correctly
 *          the MI call times out because the switch is busy
 *          a warning is logged
 *   ...    no other customer changes today, so the content never changes again
 *          and there is never another reload attempt
 *
 * The leaked password keeps working. The old comment claimed "the next
 * successful reload fixes everything at once", which was true except that
 * there was no next reload.
 *
 * So publication is a STATE, not an event: a changed write sets a flag, and
 * only an acknowledged reload clears it. Every tick retries while it is set.
 *
 * It is a class rather than a loop in main() because that is what made it
 * testable — the original lived in a private function and could not be
 * exercised at all, which is part of why the gap survived review.
 */
class CredentialPublisher(
    private val file: SubscriberFile,
    private val reloader: SwitchReloader,
    private val realm: String,
    private val log: (String) -> Unit = { System.err.println(it) },
) {

    /** Set by a changed write, cleared only by an acknowledged reload. */
    @Volatile
    private var reloadPending = false

    /** True while the switch has not confirmed it re-read the file. */
    val pending: Boolean get() = reloadPending

    /**
     * One cycle. Safe to call on a timer; does nothing when there is nothing
     * to do.
     *
     * @return true if the switch is now known to be up to date.
     */
    fun publish(store: Store): Boolean {
        try {
            if (file.writeFrom(store, realm)) {
                log("subscriber file updated")
                reloadPending = true
            }
        } catch (failure: Throwable) {
            // Never fatal. A provisioning API that dies because a switch's
            // credential file could not be written takes the business offline
            // over a file the business can run without for a few seconds.
            // Loud, though: silence here is customers who cannot log in, with
            // no reason given.
            log("WARNING: could not write the credential file: $failure")
            return false
        }

        if (!reloadPending) return true

        return if (reloader.reloadSubscribers()) {
            reloadPending = false
            true
        } else {
            // Deliberately left set. The file on disk is already correct, so
            // the next tick fixes it — which is only true because the flag
            // survives to make that tick try again.
            log("WARNING: the switch has not reloaded the credential file; will retry")
            false
        }
    }
}
