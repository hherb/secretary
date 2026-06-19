package org.secretary.app

import android.os.Bundle
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface

/**
 * The single Activity (a `FragmentActivity`, required by `androidx.biometric`) for the walking skeleton.
 * Sets FLAG_SECURE so the password field never appears in screenshots or the app-switcher snapshot
 * (the cheap stand-in for iOS's PrivacyCover; a full cover is deferred with browse). Hosts the Compose
 * [AppRoot].
 */
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        setContent {
            MaterialTheme {
                Surface {
                    AppRoot()
                }
            }
        }
    }
}
