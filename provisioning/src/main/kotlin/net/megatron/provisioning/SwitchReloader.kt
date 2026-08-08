package net.megatron.provisioning

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * Tells the switch to re-read the credential file.
 *
 * WHY THIS IS NOT OPTIONAL. OpenSIPS's db_text module loads its tables into
 * memory once, at startup, and answers every lookup from there. A file that
 * changes on disk changes nothing at all until the switch is asked to reload
 * it. Without that call, every part of the credential path appeared to work
 * and none of it did:
 *
 *   - a new customer's credential reached the file, and they still could not
 *     register;
 *   - a rotated password left the OLD one working, indefinitely — a rotation
 *     that rotates nothing is worse than not offering one, because the
 *     customer who rotated because their password leaked believes they are
 *     safe;
 *   - a suspended account kept registering forever.
 *
 * All three are silent from provisioning's side, where the write succeeded.
 *
 * A FAILED RELOAD IS NOT FATAL, AND IS LOUD. The file on disk is already
 * correct, so the next successful reload fixes everything at once. Taking
 * provisioning down because the switch's management interface was briefly
 * unreachable would trade a delayed credential for an offline business.
 */
open class SwitchReloader(
    private val miUrl: String?,
    private val log: (String) -> Unit = { System.err.println(it) },
) {

    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(3))
        .build()

    /** True if the switch acknowledged the reload. */
    open fun reloadSubscribers(): Boolean {
        if (miUrl.isNullOrBlank()) {
            // Deliberately not silent. "No reload configured" and "reload
            // failed" have completely different fixes, and an operator whose
            // customers cannot register needs to know which one they have.
            if (!warnedAboutMissingUrl) {
                warnedAboutMissingUrl = true
                log(
                    "NOTE: MEGATRON_SWITCH_MI_URL is not set, so the switch is never told " +
                        "to reload the credential file. New customers will not be able to " +
                        "register, and rotated passwords will not take effect, until it is " +
                        "set (for example http://127.0.0.1:8888/mi) or the switch is " +
                        "restarted."
                )
            }
            return false
        }

        return try {
            val request = HttpRequest.newBuilder()
                .uri(URI.create(miUrl))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .POST(
                    HttpRequest.BodyPublishers.ofString(
                        """{"jsonrpc":"2.0","id":1,"method":"dbt_reload"}"""
                    )
                )
                .build()
            val response = client.send(request, HttpResponse.BodyHandlers.ofString())

            // OpenSIPS answers JSON-RPC, which returns HTTP 200 with an
            // "error" member when the method itself failed. A status check
            // alone would report a refused reload as a successful one.
            val body = response.body()
            if (response.statusCode() != 200 || body.contains("\"error\"")) {
                log("WARNING: the switch refused the credential reload: ${response.statusCode()} $body")
                false
            } else {
                true
            }
        } catch (failure: Exception) {
            log("WARNING: could not reach the switch to reload credentials: $failure")
            false
        }
    }

    private var warnedAboutMissingUrl = false
}
