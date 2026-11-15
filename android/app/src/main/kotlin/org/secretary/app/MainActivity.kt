package org.secretary.app

import android.os.Bundle
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.Surface
import org.secretary.browse.setPlatformSyncStateDir

/**
 * The single Activity (a `FragmentActivity`, required by `androidx.biometric`) for the walking skeleton.
 * Sets FLAG_SECURE so the password field never appears in screenshots or the app-switcher snapshot
 * (the cheap stand-in for iOS's PrivacyCover; a full cover is deferred with browse). Hosts the Compose
 * [AppRoot].
 */
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Before any open: the rollback check must read the baseline this app's sync writes (#746).
        // Activity recreation repeats the same path, which the bridge treats as a no-op.
        installPlatformSyncStateDir(filesDir, ::setPlatformSyncStateDir)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        setContent {
            SecretaryTheme {
                Surface(color = androidx.compose.material3.MaterialTheme.colorScheme.background) {
                    AppRoot()
                }
            }
        }
    }
}
