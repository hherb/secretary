package org.secretary.app

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class UnlockBiometricEnrolledTest {
    @Test fun cloudTarget_enrolled_isTrue() {
        assertTrue(unlockBiometricEnrolled(isCloudTarget = true, demoEnrolled = false, cloudEnrolled = true))
    }

    @Test fun cloudTarget_unenrolled_isFalse() {
        assertFalse(unlockBiometricEnrolled(isCloudTarget = true, demoEnrolled = true, cloudEnrolled = false))
    }

    @Test fun demoTarget_followsDemoEnrolled_true() {
        assertTrue(unlockBiometricEnrolled(isCloudTarget = false, demoEnrolled = true, cloudEnrolled = false))
    }

    @Test fun demoTarget_followsDemoEnrolled_false() {
        assertFalse(unlockBiometricEnrolled(isCloudTarget = false, demoEnrolled = false, cloudEnrolled = true))
    }

    @Test fun cloudBranch_ignoresDemoEnrolled() {
        // cloud target: demoEnrolled must not leak in
        assertFalse(unlockBiometricEnrolled(isCloudTarget = true, demoEnrolled = true, cloudEnrolled = false))
    }

    @Test fun demoBranch_ignoresCloudEnrolled() {
        // demo target: cloudEnrolled must not leak in
        assertFalse(unlockBiometricEnrolled(isCloudTarget = false, demoEnrolled = false, cloudEnrolled = true))
    }
}
