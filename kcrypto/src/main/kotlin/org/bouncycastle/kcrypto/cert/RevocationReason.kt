package org.bouncycastle.kcrypto.cert

enum class RevocationReason(val value: Int) {
    unspecified(0),
    keyCompromise(1),
    cACompromise(2),
    affiliationChanged(3),
    superseded(4),
    cessationOfOperation(5),
    certificateHold(6),
    // 7 -> unknown
    removeFromCRL(8),
    privilegeWithdrawn(9),
    aACompromise(10)
}