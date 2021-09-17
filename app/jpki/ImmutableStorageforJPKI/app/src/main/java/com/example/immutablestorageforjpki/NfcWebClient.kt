package com.example.immutablestorageforjpki

import android.content.res.Resources
import android.net.Uri
import android.net.http.SslError
import android.nfc.Tag
import android.util.Base64
import android.webkit.*
import java.io.InputStream

class NfcWebClient: WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        if ( Uri.parse(view?.url).host == ImmStorageHost ) {
            return false
        }
        return super.shouldOverrideUrlLoading(view, request)
    }

    override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
        if ( Uri.parse(view?.url).host == ImmStorageHost ) {
            handler?.proceed()
            return
        }
        super.onReceivedSslError(view, handler, error)
    }
}

@ExperimentalUnsignedTypes
class WebAppNfc(private val tag: Tag, private val res: Resources) {
    @JavascriptInterface
    fun isJPKI(): Boolean {
        tag.techList?.let {
            var expectedTypeF = false
            for (tech in it ) {
                if ( tech == "android.nfc.tech.IsoDep" ) {
                    expectedTypeF = true
                    break
                }
            }

            if (expectedTypeF == false) {
                return expectedTypeF
            }
        }

        return HndIsoDep(tag).isJPKI()
    }

    @JavascriptInterface
    fun readAuthCert(): String {
        return HndIsoDep(tag).readAuthCert()
    }

    @JavascriptInterface
    fun readAuthCACert(): String {
        return HndIsoDep(tag).readAuthCACert()
    }

    @JavascriptInterface
    fun readSignCert(pin: String): String {
        return HndIsoDep(tag).readSignCert(pin)
    }

    @JavascriptInterface
    fun readSignCACert(): String {
        return HndIsoDep(tag).readSignCACert()
    }

    @JavascriptInterface
    fun signData(pin: String, digest: String): String {
        return HndIsoDep(tag).signRawData(pin, digest)
    }

    @JavascriptInterface
    fun signDataUsingAuthKey(pin: String, digest: String): String {
        return HndIsoDep(tag).signRawDataUsingAuthKey(pin, digest)
    }

    @JavascriptInterface
    fun readNfcWasm(): String {
        val ins :InputStream = res.openRawResource(R.raw.jpkiweb)
        val rawLen = ins.available()
        val rawData = ByteArray(rawLen)
        val readLen = ins.read(rawData)
        if ( (readLen != -1) && (readLen != rawLen)  ) {
            return ""// error
        }

        return Base64.encodeToString(rawData, Base64.DEFAULT)
    }
}