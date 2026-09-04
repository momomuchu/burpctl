package com.burprest

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import com.burprest.server.RestServer

class BurpRestExtension : BurpExtension {

    private var server: RestServer? = null

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Burp REST API")

        val port = System.getProperty("burp.rest.port")?.toIntOrNull() ?: 8089

        server = RestServer(api, port)
        server!!.start()

        api.extension().registerUnloadingHandler {
            server?.stop()
        }

        api.logging().logToOutput(
            """
            |Burp REST API Extension v$EXTENSION_VERSION
            |  API:    http://127.0.0.1:$port
            |  Docs:   http://127.0.0.1:$port/docs
            |  Health: http://127.0.0.1:$port/health
            """.trimMargin()
        )
    }
}
