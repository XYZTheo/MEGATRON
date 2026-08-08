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

            // FORCED TO DISK BEFORE THE RENAME, or "atomic" only means atomic
            // against other PROCESSES.
            //
            // ATOMIC_MOVE says nothing about a power cut. ext4 can make the
            // rename durable while the file's contents are not, which leaves a
            // zero-length subscriber table — and by this class's own argument
            // that is not a few lost customers, it is db_text refusing to load
            // the table at all and EVERY customer unable to register, after a
            // reboot, with no sign of what happened.
            java.io.FileOutputStream(temporary.toFile(), true).use { it.fd.sync() }

            Files.move(
                temporary, path,
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE,
            )

            // And the directory, so the rename itself survives. Best-effort:
            // opening a directory for read is POSIX-specific and fails on
            // Windows, where this code only ever runs in tests. Losing the
            // durability of the rename is recoverable — the next write redoes
            // it — so it must not be the thing that stops the file being
            // written at all.
            runCatching {
                java.nio.channels.FileChannel.open(directory).use { it.force(true) }
            }
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
    fun writeFrom(store: Store, realm: String): Boolean {
        val active = allActive(store)
        val content = SubscriberExport.render(active, { store.sipDigestHa1(it, realm) }, realm)
        val rows = content.lines().count { it.isNotBlank() } - 1

        // AN EMPTY FILE NEVER OVERWRITES A POPULATED ONE.
        //
        // The realm is baked into every stored HA1. Point this at a realm the
        // store holds no credentials for — a typo in MEGATRON_SIP_REALM is
        // enough — and sipDigestHa1 returns null for every customer, render
        // skips them all, and a header-only file lands on top of a working
        // one. Every customer's login disappears within one interval, the
        // write reports success, and nothing is logged as a problem.
        //
        // The doc on this class used to claim a realm mismatch "produces HA1
        // values no phone can satisfy". It does not; it produces no rows at
        // all, which is a different failure with a different diagnosis and a
        // much wider blast radius.
        //
        // Refusing is safe: a stale credential file keeps existing customers
        // working while somebody reads the error. Writing is not.
        if (rows == 0 && active.isNotEmpty()) {
            throw IllegalStateException(
                "refusing to write an empty subscriber file: ${active.size} active " +
                    "customer(s) exist but none has a credential for realm '$realm'. " +
                    "Check MEGATRON_SIP_REALM matches the realm the credentials were " +
                    "created under."
            )
        }
        return write(content)
    }

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
