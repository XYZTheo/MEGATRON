package net.megatron.bot

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [HttpTelegramApi] against a real HTTP server.
 *
 * The loop is tested against a fake TelegramApi, which proves the decisions
 * but not the wire format — and the wire format is where an untested
 * transport actually breaks. This uses the JDK's own HTTP server so the
 * request is really built, really sent, and really parsed, with no new
 * dependency and nothing to configure.
 *
 * The JSON bodies below are copied from Telegram's Bot API documentation
 * rather than invented, including the fields this bot ignores. A parser tested
 * only against the subset it expects passes right up until it meets a real
 * message.
 */
class HttpTelegramApiTest {

    private lateinit var server: HttpServer
    private lateinit var api: HttpTelegramApi

    private val token = "123456:FAKE-TOKEN-NOT-A-REAL-ONE"

    /** Whatever the next request should get back. */
    private var response = "{}"
    private var status = 200

    /** What the server actually received, so the request can be asserted on. */
    private val requests = mutableListOf<Pair<String, String>>()

    @BeforeTest
    fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { exchange: HttpExchange ->
            val body = exchange.requestBody.readBytes().decodeToString()
            requests += exchange.requestURI.path to body
            val bytes = response.toByteArray()
            exchange.sendResponseHeaders(status, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
        api = HttpTelegramApi(token, "http://127.0.0.1:${server.address.port}")
    }

    @AfterTest
    fun stop() = server.stop(0)

    // -- reading updates ------------------------------------------------------

    @Test
    fun `a real-shaped update is parsed`() {
        response = """
        {"ok":true,"result":[{
          "update_id":870123,
          "message":{
            "message_id":42,
            "from":{"id":555,"is_bot":false,"first_name":"Seth","language_code":"en"},
            "chat":{"id":555,"first_name":"Seth","type":"private"},
            "date":1786152000,
            "text":"/balance"
          }
        }]}
        """.trimIndent()

        val updates = api.getUpdates(0, 1)

        assertEquals(1, updates.size)
        assertEquals(
            Incoming(
                updateId = 870123,
                telegramUserId = 555,
                chatId = 555,
                messageId = 42,
                text = "/balance",
                chatType = "private",
            ),
            updates.single(),
        )
    }

    @Test
    fun `a group message keeps its negative chat id and its type`() {
        // Both matter: the chat id is negative for groups and must survive the
        // round trip intact, and the type is what stops a SIP password being
        // posted where everyone can read it.
        response = """
        {"ok":true,"result":[{
          "update_id":2,
          "message":{
            "message_id":9,
            "from":{"id":555,"is_bot":false,"first_name":"Seth"},
            "chat":{"id":-1001234567890,"title":"ops","type":"supergroup"},
            "date":1786152000,
            "text":"/users"
          }
        }]}
        """.trimIndent()

        val update = api.getUpdates(0, 1).single()
        assertEquals(-1001234567890L, update.chatId)
        assertEquals("supergroup", update.chatType)
    }

    @Test
    fun `a message with no text is dropped, not turned into an empty command`() {
        // Photos, stickers, and someone joining the group all arrive here.
        // None is an error and none is a command.
        response = """
        {"ok":true,"result":[
          {"update_id":1,"message":{"message_id":1,
            "from":{"id":555},"chat":{"id":555,"type":"private"},
            "date":1,"sticker":{"file_id":"abc"}}},
          {"update_id":2,"message":{"message_id":2,
            "from":{"id":555},"chat":{"id":555,"type":"private"},
            "date":1,"text":"/help"}}
        ]}
        """.trimIndent()

        val updates = api.getUpdates(0, 1)
        assertEquals(1, updates.size)
        assertEquals("/help", updates.single().text)
    }

    @Test
    fun `an update that is not a message at all is dropped`() {
        // allowed_updates asks Telegram not to send these, but the parser must
        // not depend on the server honouring a request.
        response = """
        {"ok":true,"result":[
          {"update_id":1,"edited_message":{"message_id":1,
            "from":{"id":555},"chat":{"id":555,"type":"private"},"text":"x"}},
          {"update_id":2,"my_chat_member":{"chat":{"id":555,"type":"private"}}}
        ]}
        """.trimIndent()

        assertEquals(emptyList(), api.getUpdates(0, 1))
    }

    @Test
    fun `an empty result is not an error`() {
        response = """{"ok":true,"result":[]}"""
        assertEquals(emptyList(), api.getUpdates(0, 1))
    }

    @Test
    fun `the offset and long-poll timeout are actually sent`() {
        // If the offset never reaches Telegram, every batch is redelivered
        // forever -- the failure that makes a /credit into unlimited credit.
        response = """{"ok":true,"result":[]}"""
        api.getUpdates(931, 25)

        val (path, body) = requests.single()
        assertEquals("/bot$token/getUpdates", path)
        assertTrue(body.contains("\"offset\":931"), body)
        assertTrue(body.contains("\"timeout\":25"), body)
        assertTrue(body.contains("message"), "allowed_updates was not restricted: $body")
    }

    // -- sending --------------------------------------------------------------

    @Test
    fun `sendMessage posts the chat id and the text`() {
        response = """{"ok":true,"result":{"message_id":1}}"""
        assertTrue(api.sendMessage(-100L, "hello"))

        val (path, body) = requests.single()
        assertEquals("/bot$token/sendMessage", path)
        assertTrue(body.contains("\"chat_id\":-100"), body)
        assertTrue(body.contains("hello"), body)
    }

    @Test
    fun `a rejected send reports failure rather than pretending`() {
        // 403 is what Telegram returns when the bot may not message a user --
        // the exact case that must not silently fall back to posting a
        // credential in a group.
        status = 403
        response = """{"ok":false,"description":"bot can't initiate conversation"}"""
        assertTrue(!api.sendMessage(555L, "secret"))
    }

    @Test
    fun `a newline in the reply survives`() {
        // Every multi-line reply the engine produces goes through JSON
        // encoding; a transport that mangled them would turn /help into one
        // long line and /newuser into an unreadable credential.
        response = """{"ok":true,"result":{}}"""
        api.sendMessage(1L, "line one\nline two")
        assertTrue(requests.single().second.contains("""line one\nline two"""))
    }

    // -- the token ------------------------------------------------------------

    /** Captures whatever the call writes to stderr. */
    private fun stderrOf(block: () -> Unit): String {
        val captured = StringBuilder()
        val original = System.err
        System.setErr(java.io.PrintStream(object : java.io.OutputStream() {
            override fun write(b: Int) { captured.append(b.toChar()) }
        }))
        try {
            block()
        } finally {
            System.setErr(original)
        }
        return captured.toString()
    }

    @Test
    fun `an error message carrying the URL has the token replaced`() {
        // THE TOKEN IS IN THE URL. Several failures put the URI in their
        // message -- a malformed base, a connect timeout, a redirect loop --
        // and logging one unmodified writes a full bot token, total compromise
        // of this surface, into the log. This uses a base URL that makes
        // URI.create throw with the whole string in the message, so the scrub
        // is exercised deterministically rather than depending on which
        // exception a network happens to produce.
        val errors = stderrOf {
            HttpTelegramApi(token, "http://127.0.0.1:1 not a url").sendMessage(1L, "x")
        }

        assertTrue(errors.isNotEmpty(), "the failure was not reported at all")
        assertTrue(!errors.contains(token), "the bot token was written to the log: $errors")
        assertTrue(errors.contains("<token>"), "the scrub did not run: $errors")
    }

    @Test
    fun `an ordinary connection failure is reported without the token`() {
        // The common case. ConnectException's own message happens not to carry
        // the URI on this JDK, which is exactly why the assertion is "the
        // token is absent" rather than "the scrub visibly fired" -- the second
        // would pass or fail on an implementation detail of the exception
        // rather than on the property that matters.
        val errors = stderrOf {
            HttpTelegramApi(token, "http://127.0.0.1:1").sendMessage(1L, "x")
        }

        assertTrue(errors.isNotEmpty(), "the failure was not reported at all")
        assertTrue(!errors.contains(token), "the bot token was written to the log: $errors")
    }

    @Test
    fun `a non-200 response is reported as unavailable, not as no updates`() {
        // REWRITTEN. This test previously asserted that a 429 yields an empty
        // list, on the reasoning that nothing may take the bot down -- true,
        // and it does not follow. Collapsing "Telegram said 429 in 3ms" into
        // the same value as "Telegram was quiet for 30 seconds" left the
        // polling loop with nothing to pace it, so the bot's response to being
        // rate-limited was to poll flat out. The test pinned the defect.
        //
        // The exception is caught by BotLoop.run(), which backs off. Nothing
        // takes the bot down; it now knows the difference.
        status = 429
        response = """{"ok":false,"parameters":{"retry_after":30}}"""
        kotlin.test.assertFailsWith<TelegramUnavailable> { api.getUpdates(0, 1) }
    }

    @Test
    fun `a malformed body is reported as unavailable`() {
        response = "this is not json"
        kotlin.test.assertFailsWith<TelegramUnavailable> { api.getUpdates(0, 1) }
    }

    @Test
    fun `one malformed update does not discard the whole batch`() {
        // kotlinx's .jsonObject and .jsonPrimitive THROW on a wrong-shaped
        // field. Parsing the batch as a single expression meant one bad update
        // discarded every good one alongside it AND left the offset unmoved,
        // so the same batch returned and threw again, forever -- the exact
        // wedge the loop's own guard was written to prevent, one layer too low
        // to catch it.
        response = """
        {"ok":true,"result":[
          {"update_id":1,"message":{"message_id":1,"from":{"id":"not-a-number"},
            "chat":{"id":555,"type":"private"},"text":"/help"}},
          {"update_id":2,"message":{"message_id":2,"from":{"id":555},
            "chat":{"id":555,"type":"private"},"text":"/balance"}}
        ]}
        """.trimIndent()

        val updates = api.getUpdates(0, 1)
        assertEquals(1, updates.size, "a good update was discarded with the bad one")
        assertEquals("/balance", updates.single().text)
    }
}
