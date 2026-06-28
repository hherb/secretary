package org.secretary.mirror

import java.io.File

/**
 * A working-copy mirror bound to one vault's [workingDir] and cloud folder: pull cloud→working
 * ([materialize]) and push working→cloud ([flush]). A thin seam over [VaultMirror] so the
 * coordinator can be host-tested with an order-recording fake and `:app` can bind the real one.
 */
interface WorkingCopyMirror {
    fun materialize(): MirrorReport
    fun flush(): MirrorReport
}

/** Binds a [VaultMirror] (built from a [CloudFolderPort]) to a fixed [workingDir]. */
class VaultMirrorWorkingCopy(private val mirror: VaultMirror, private val workingDir: File) : WorkingCopyMirror {
    override fun materialize(): MirrorReport = mirror.materialize(workingDir)
    override fun flush(): MirrorReport = mirror.flush(workingDir)
}
