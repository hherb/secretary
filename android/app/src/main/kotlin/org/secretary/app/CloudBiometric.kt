package org.secretary.app

/**
 * Whether the unlock screen should offer biometric unlock for the current target.
 *
 * The unlock screen serves both the demo/local vault and a cloud (SAF) vault. The biometric
 * affordance is enrollment-scoped per target: a cloud target uses its own per-cloud-vault enclave
 * ([cloudEnrolled]), the demo target uses the demo enclave ([demoEnrolled]). This is the single
 * decision that replaces the old demo-only inline check (`cloudTarget == null && state is Enrolled`)
 * now that cloud open supports biometrics too.
 *
 * Pure and total: a cloud target follows [cloudEnrolled] and never [demoEnrolled], a demo target
 * follows [demoEnrolled] and never [cloudEnrolled] — no cross-talk between the two namespaces.
 */
fun unlockBiometricEnrolled(
    isCloudTarget: Boolean,
    demoEnrolled: Boolean,
    cloudEnrolled: Boolean,
): Boolean = if (isCloudTarget) cloudEnrolled else demoEnrolled
