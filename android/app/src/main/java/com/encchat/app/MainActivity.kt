package com.encchat.app
import android.annotation.SuppressLint
import android.os.Bundle
import android.view.WindowManager
import android.webkit.*
import androidx.appcompat.app.AppCompatActivity
class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN)
        setContentView(R.layout.activity_main)
        webView = findViewById(R.id.webview)
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            cacheMode = WebSettings.LOAD_NO_CACHE
            userAgentString = "EncchatApp/1.0"
        }
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val url = request?.url?.toString() ?: return true
                return !url.startsWith("https://geo.encchat.workers.dev")
            }
            override fun onPageFinished(view: WebView?, url: String?) {
                view?.evaluateJavascript("""
                    (function() {
                        var badge = document.getElementById('android-badge');
                        var info = document.getElementById('apk-info');
                        if (badge) badge.style.display = 'none';
                        if (info) info.style.display = 'none';
                    })();
                """.trimIndent(), null)
            }
        }
        webView.webChromeClient = WebChromeClient()
        webView.loadUrl("https://geo.encchat.workers.dev")
    }
    override fun onBackPressed() {
        if (webView.canGoBack()) webView.goBack() else super.onBackPressed()
    }
}
