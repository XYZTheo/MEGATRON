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
class SubscriberFile(
    private val path: Path,
    private val log: (String) -> Unit = { System.err.println(it) },
) {

    /**
     * How many credential rows the file on disk currently has.
     *
     * The question the guard actually needs to answer is "would this write
     * DESTROY credentials", and only the file can answer that — the render is
     * empty in both the dangerous case and the harmless one.
     */
    private fun existingRowCount(): Int =
        runCatching {
            Files.readAllLines(path).count { it.isNotBlank() } - 1
        }.getOrDefault(0).coerceAtLeast(0)

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

        // AN EMPTY RENDER NEVER OVERWRITES A POPULATED FILE — AND THAT IS NOT
        // THE SAME AS "NEVER WRITES AN EMPTY FILE".
        //
        // The realm is baked into every stored HA1. Point this at a realm the
        // store holds no credentials for — a typo in MEGATRON_SIP_REALM is
        // enough — and every lookup misses, every customer is skipped, and a
        // header-only file lands on top of a working one. Every login
        // disappears within one interval and the write reports success.
        //
        // The first guard refused whenever the render was empty and customers
        // existed, which was WORSE than the bug for two ordinary states:
        //
        //   - a database just migrated to store HA1, where every existing
        //     customer legitimately has none yet;
        //   - a MagnusBilling import, same thing.
        //
        // There the file was never created at all, and a MISSING table makes
        // auth_db report "table 'subscriber' does not exist" — a 500 on every
        // REGISTER, which is the exact failure the header-only file avoids.
        // The error also blamed MEGATRON_SIP_REALM, sending the operator to
        // hunt a mismatch that did not exist.
        //
        // So the question is not "is the render empty" but "are we DESTROYING
        // credentials that were there a moment ago". Going from populated to
        // empty is a realm mismatch; starting empty is a new or migrated
        // deployment, and it gets a header so the switch can load a table.
        if (rows == 0 && active.isNotEmpty() && existingRowCount() > 0) {
            throw IllegalStateException(
                "refusing to blank a populated subscriber file: ${active.size} active " +
                    "customer(s) exist and none has a credential for realm '$realm', " +
                    "but the file currently on disk has ${existingRowCount()}. Check " +
                    "MEGATRON_SIP_REALM matches the realm the credentials were created " +
                    "under."
            )
        }
        if (rows == 0 && active.isNotEmpty()) {
            log(
                "NOTE: writing a subscriber file with no credentials. ${active.size} active " +
                    "customer(s) exist but none has a SIP digest credential yet — usual " +
                    "after an upgrade or an import. They cannot register until their " +
                    "credentials are rotated (/rotate <handle>, or " +
                    "POST /v1/customers/{id}/credentials)."
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
