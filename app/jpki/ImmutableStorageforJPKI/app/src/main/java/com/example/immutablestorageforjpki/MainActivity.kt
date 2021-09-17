package com.example.immutablestorageforjpki

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.content.res.Resources
import android.nfc.NfcAdapter
import android.nfc.Tag
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.webkit.WebView
import android.widget.TextView
import androidx.activity.viewModels
import androidx.lifecycle.*
import kotlinx.coroutines.launch
import java.io.InputStream
import kotlin.ExperimentalUnsignedTypes as KotlinExperimentalUnsignedTypes

val ImmStorageHost: String = "192.168.0.1"

@kotlin.ExperimentalUnsignedTypes
class RoadWasm() : ViewModel() {
    val mutHtml = MutableLiveData<String>()
    val htmlStr: LiveData<String>
        get() = mutHtml

    fun readRawResource(res: Resources, id: Int): String {
        val ins: InputStream = res.openRawResource(id)
        val len: Int = ins.available()
        val raw = ByteArray(len)
        val readLen:Int = ins.read(raw)
        if ( (readLen != -1) && (readLen != len) ) {
            return "" // error
        }

        return String(raw)
    }

    fun roadData(res: Resources) {
        var cssStr: String = readRawResource(res, R.raw.jpkiweb_style)
        var wasmExecStr: String = readRawResource(res, R.raw.wasm_exec)
        var html: String = readRawResource(res, R.raw.jpki)
        if ( (cssStr == "") || (wasmExecStr == "") || (html == "") ) {
            return
        }

        cssStr = "<style>\n" + cssStr + "\n</style>\n"
        html = html.replace("  <link rel=\"stylesheet\" href=\"jpkiweb_style.css\">", cssStr)

        wasmExecStr = "<script>\n" + wasmExecStr + "\n</script>\n"
        html = html.replace("  <script src=\"wasm_exec.js\"></script>", wasmExecStr)

        mutHtml.postValue(html)
        return
    }
}

@kotlin.ExperimentalUnsignedTypes
class MainActivity : AppCompatActivity() {
    var nfcAdapter: NfcAdapter? = null
    private val vModel: RoadWasm by viewModels()
    lateinit var wasmView: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val nfcStatus: TextView? = findViewById<TextView>(R.id.nfcStatus)
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter?.isEnabled() == false) {
            nfcStatus?.setText(R.string.nfc_disabled)
            return
        }
        nfcStatus?.setText(R.string.touch_card)

        wasmView = findViewById<WebView>(R.id.wasmView)?.also {
            if (savedInstanceState == null) {
                vModel.roadData(resources)
            }
        }!!
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)

        if (intent?.action != NfcAdapter.ACTION_TAG_DISCOVERED) {
            return
        }

        intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)?.let { tag ->
            wasmView.also {
                it.addJavascriptInterface(WebAppNfc(tag, resources), "webAppNfc")

                vModel.htmlStr.observe(this, Observer { html ->
                    it.settings.javaScriptEnabled = true
                    it.settings.domStorageEnabled = true
                    it.webViewClient = NfcWebClient()

                    val baseUrl = "https://"+ImmStorageHost
                    it.loadDataWithBaseURL(baseUrl, html, "text/html; charset=UTF-8", null, baseUrl)
                    //it.loadUrl("https://"+ ImmStorageHost+"/jpki.html")
                })
            }
        }
    }

    @SuppressLint("UnspecifiedImmutableFlag")
    override fun onResume() {
        super.onResume()
        val pendingIntent: PendingIntent = PendingIntent.getActivity(this, 0,
            Intent(this, javaClass).apply {
                addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            }, 0)
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, null, null)
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        wasmView.also{
            it.saveState(outState)
        }
    }

    override fun onRestoreInstanceState(savedInstanceState: Bundle) {
        super.onRestoreInstanceState(savedInstanceState)
        wasmView.also {
            it.restoreState(savedInstanceState)
        }
    }
}