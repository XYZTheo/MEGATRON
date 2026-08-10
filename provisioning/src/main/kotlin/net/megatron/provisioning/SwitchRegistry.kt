package net.megatron.provisioning

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Whether a customer's phone is actually registered, asked of the switch.
 *
 * "Is their phone online" is the first question an operator asks when a
 * customer says calls are not working, and it is the one question the database
 * cannot answer: registrations are soft state living in OpenSIPS's memory, not
 * in any table MEGATRON owns. So this asks the switch, over the same loopback
 * MI interface used to reload credentials.
 *
 * NOT AUTHORITATIVE ABOUT MONEY, and deliberately so. A registered phone is
 * not permission to call and an unregistered one is not a suspension — the
 * authorizer decides that live, per call, from the balance. This is
 * diagnostics.
 */
@Serializable
data class RegistrationStatus(
    val registered: Boolean,
    /** Where the phone is registered from, as the switch sees it. */
    val contact: String? = null,
    @SerialName("user_agent") val userAgent: String? = null,
    @SerialName("expires_seconds") val expiresSeconds: Int? = null,
    /**
     * True when the switch could not be asked at all.
     *
     * "Not registered" and "we could not tell" are different answers to an
     * operator deciding whether to wake a customer at 2am, so they are
     * different fields rather than the same false.
     */
    val unknown: Boolean = false,
)

/**
 * Reads registrations from OpenSIPS over MI.
 *
 * Uses `ul_show_contact` for ONE address of record rather than `ul_dump` for
 * all of them: dumping the whole location table to answer a question about one
 * customer costs the switch more the busier it gets, which is exactly when an
 * operator is asking.
 */
open class SwitchRegistry(
    private val miUrl: String?,
    private val log: (String) -> Unit = { System.err.println(it) },
) {

    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(3))
        .build()

    private val json = Json { ignoreUnknownKeys = true }

    open fun registrationFor(handle: String): RegistrationStatus {
        if (miUrl.isNullOrBlank()) return RegistrationStatus(registered = false, unknown = true)

        // The handle is JSON-quoted rather than interpolated. Handle
        // validation makes a quote or backslash unreachable today, and that
        // validation lives in another file — the same argument that put an
        // escape check in SubscriberExport.
        val aor = kotlinx.serialization.json.JsonPrimitive(handle).toString()
        val body = """{"jsonrpc":"2.0","id":1,"method":"ul_show_contact",""" +
            """"params":{"table_name":"location","aor":$aor}}"""

        val response = try {
            val request = HttpRequest.newBuilder()
                .uri(URI.create(miUrl))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build()
            client.send(request, HttpResponse.BodyHandlers.ofString())
        } catch (failure: Exception) {
            log("WARNING: could not ask the switch about '$handle': $failure")
            return RegistrationStatus(registered = false, unknown = true)
        }

        if (response.statusCode() != 200) {
            log("WARNING: the switch answered ${response.statusCode()} for '$handle'")
            return RegistrationStatus(registered = false, unknown = true)
        }

        return parse(response.body())
    }

    /**
     * Parses `ul_show_contact`'s answer.
     *
     * The shapes below were copied from a real switch with a real
     * registration, not from documentation — the last time a response format
     * was assumed here, every call reported "unknown media" for a week.
     *
     * A JSON-RPC "error" member is the switch saying the AOR is not
     * registered. That is a legitimate NO, not a failure to ask: an
     * unregistered customer is the normal case.
     */
    internal fun parse(payload: String): RegistrationStatus {
        val root = try {
            json.parseToJsonElement(payload).jsonObject
        } catch (malformed: Exception) {
            log("WARNING: the switch sent something that is not JSON: $malformed")
            return RegistrationStatus(registered = false, unknown = true)
        }

        if (root.containsKey("error")) return RegistrationStatus(registered = false)

        val contacts = try {
            root["result"]?.jsonObject?.get("Contacts")?.jsonArray
        } catch (unexpected: Exception) {
            log("WARNING: unexpected ul_show_contact shape: $unexpected")
            return RegistrationStatus(registered = false, unknown = true)
        }

        // An AOR with an empty contact list is a phone that unregistered.
        val contact = contacts?.firstOrNull()?.jsonObject
            ?: return RegistrationStatus(registered = false)

        fun text(key: String) = contact[key]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }

        return RegistrationStatus(
            registered = true,
            contact = text("Contact"),
            // Hyphenated, and it is "User-agent" rather than "User-Agent" —
            // taken from the wire, because guessing the capitalisation returns
            // a silent null that looks like a phone not reporting one.
            userAgent = text("User-agent"),
            expiresSeconds = contact["Expires"]?.jsonPrimitive?.intOrNull,
        )
    }
}
