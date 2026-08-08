package net.megatron.bot

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The wire parser, attacked with responses that are not the happy path.
 */
class HttpTelegramApiHostileTest {

    private lateinit var server: HttpServer
    private lateinit var api: HttpTelegramApi

    private var response = "{}"
    private var status = 200

    @BeforeTest
    fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { exchange: HttpExchange ->
            exchange.requestBody.readBytes()
            val bytes = response.toByteArray()
            exchange.sendResponseHeaders(status, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
        api = HttpTelegramApi("123456:FAKE-TOKEN-NOT-A-REAL-ONE",
            "http://127.0.0.1:${server.address.port}")
    }

    @AfterTest
    fun stop() = server.stop(0)

    /**
     * chat.type is the ONLY thing standing between /newuser and a SIP password
     * in permanent group history, and parseUpdate defaults it to "private" when
     * the field is missing or is not a string.
     *
     * A default on a security control has to be the SAFE answer. "private" is
     * the unsafe one: BotLoop sends a secret reply straight back to
     * update.chatId whenever chatType == "private".
     *
     * The chat id here is negative, which is Telegram's own unambiguous signal
     * that this is a group — so the information needed to fail closed is
     * present in the very object being parsed.
     */
    @Test
    fun `a chat with no type is not assumed private`() {
        response = """
        {"ok":true,"result":[{
          "update_id":1,
          "message":{
            "message_id":9,
            "from":{"id":555,"is_bot":false,"first_name":"Seth"},
            "chat":{"id":-1001234567890,"title":"ops"},
            "date":1786152000,
            "text":"/newuser bravo plan-1"
          }
        }]}
        """.trimIndent()

        val update = api.getUpdates(0, 1).single()
        assertTrue(
            update.chatType != "private",
            "a group chat with no type field parsed as chatType=\"private\" " +
                "(chat id ${update.chatId}), so BotLoop will post the credential " +
                "into the group",
        )
    }

    /**
     * ONE UNPARSEABLE UPDATE WEDGES THE BOT.
     *
     * parseUpdate reaches for `.jsonPrimitive` / `.jsonObject`, both of which
     * THROW when the field is the wrong JSON shape. That throw escapes
     * getUpdates (the try in `call` covers only the HTTP exchange), so:
     *
     *  - the whole batch is lost, including the well-formed updates in it;
     *  - BotLoop.offset never advances, because no update was ever received;
     *  - BotLoop.run() catches, sleeps 5s, and asks for the same batch again.
     *
     * That is an unbounded loop on one message, which is precisely the failure
     * the commit message says was designed out: "A message that crashes the
     * handler would otherwise crash it on every poll and the bot would never
     * process anything else — the entire business stopped by one malformed
     * command." The guard is in dispatch(), one layer too late; nothing
     * protects the parser.
     */
    @Test
    fun `one malformed update does not take the whole batch down`() {
        response = """
        {"ok":true,"result":[
          {"update_id":2,"message":{
            "message_id":9,
            "from":{"id":555},
            "chat":{"id":-1001234567890,"type":{"nested":"object"}},
            "date":1786152000,
            "text":"/users"}},
          {"update_id":3,"message":{
            "message_id":10,
            "from":{"id":555},
            "chat":{"id":555,"type":"private"},
            "date":1786152000,
            "text":"/help"}}
        ]}
        """.trimIndent()

        val updates = runCatching { api.getUpdates(0, 1) }
        assertTrue(
            updates.isSuccess,
            "getUpdates threw ${updates.exceptionOrNull()}: the batch is lost, the " +
                "offset never advances, and run() will ask for the same batch every " +
                "5 seconds forever",
        )
        assertTrue(
            updates.getOrThrow().any { it.text == "/help" },
            "the well-formed update in the batch was discarded with the bad one",
        )
    }
}
