package net.megatron.provisioning

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.atomic.AtomicReference

/**
 * Writes the OpenSIPS subscriber table to disk.
 *
 * Two properties matter, and both are about a file another process is reading
 * while we write it.
 *
 * ATOMICITY. OpenSIPS re-reads this file on command. If it reads a half-written
 * one it does not get a few missing customers — db_text refuses to load a
 * malformed table, so EVERY customer stops being able to register at once,
 * during what looked like a routine provisioning update. So the content is
 * written to a temporary file in the same directory and moved into place with
 * ATOMIC_MOVE. Same directory because a move across filesystems is a copy, and
 * a copy is exactly the non-atomic write being avoided.
 *
 * IDEMPOTENCE. [write] returns false and touches nothing when the content is
 * unchanged, so the caller can run it on a short timer without making OpenSIPS
 * reload — and flush its registrar cache — every time.
 */
class SubscriberFile(private val path: Path) {

    /** The last content written, so an unchanged render costs no disk I/O. */
    private val lastWritten = AtomicReference<String?>(null)

    /**
     * @return true if the file changed and OpenSIPS should be asked to reload.
     */
    fun write(content: String): Boolean {
        if (content == lastWritten.get() && Files.exists(path)) return false

        val directory = path.toAbsolutePath().parent
        Files.createDirectories(directory)

        // Same directory: ATOMIC_MOVE is only atomic within one filesystem,
        // and the system temp directory is frequently a different one.
        val temporary = Files.createTempFile(directory, ".subscriber-", ".tmp")
        try {
            // The file is a list of password-equivalent credentials. It is
            // created 0600 and narrowed BEFORE the content is written, so
            // there is no window in which it exists and is world-readable.
            // Best-effort: on a filesystem with no POSIX permissions this
            // throws, and refusing to write the file at all would take
            // registration down over a permissions bit.
            runCatching {
                Files.setPosixFilePermissions(
                    temporary, PosixFilePermissions.fromString("rw-------"),
                )
            }
            Files.writeString(temporary, content)
            Files.move(
                temporary, path,
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE,
            )
        } catch (failure: Throwable) {
            // Leaving .tmp files behind in the directory OpenSIPS reads is not
            // harmless: db_text loads a directory, and a stray file in it is a
            // table OpenSIPS will try to parse.
            runCatching { Files.deleteIfExists(temporary) }
            // The cached content must not record a write that did not happen,
            // or the next attempt will consider itself unnecessary and skip.
            lastWritten.set(null)
            throw failure
        }

        lastWritten.set(content)
        return true
    }

    /**
     * Renders from a store and writes.
     *
     * The realm comes from the caller rather than being read back out of the
     * store, because it must be the same realm OpenSIPS is configured to
     * challenge with. A mismatch there produces HA1 values no phone can
     * satisfy, which presents as every customer being rejected with correct
     * credentials.
     */
    fun writeFrom(store: Store, realm: String): Boolean =
        write(SubscriberExport.render(allActive(store), { store.sipDigestHa1(it, realm) }, realm))

    /**
     * EVERY active customer, following the cursor to the end.
     *
     * Taking a single page would mean that past some customer count, new
     * customers simply cannot register — no error, no log line, and the
     * symptom is "the newest accounts don't work" long after whoever set the
     * limit has forgotten it exists. The loop has a bound only so a store
     * returning a cursor that never advances cannot hang provisioning.
     */
    private fun allActive(store: Store): List<Customer> {
        val all = mutableListOf<Customer>()
        var cursor: String? = null
        var pages = 0
        var empty: Boolean
        do {
            val page = store.listCustomers(CustomerStatus.ACTIVE, PAGE, cursor)
            all += page.items
            cursor = page.nextCursor
            empty = page.items.isEmpty()
            check(++pages <= MAX_PAGES) { "the customer listing did not terminate" }
        } while (cursor != null && !empty)
        return all
    }

    private companion object {
        const val PAGE = 500
        const val MAX_PAGES = 1_000
    }
}
