package com.example.ultravigilance.data.model

import com.google.gson.annotations.SerializedName

// Request body sent to /scan-document
data class ScanDocumentRequest(
    val url: String
)

// Response received from /scan-document
data class ScanDocumentResponse(
    @SerializedName("status_code")
    val statusCode: Int? = null,
    val detail: String? = null,
    val verdict: String? = null,
    val confidence: Double? = null,
    val reasons: List<String>? = null
)

// Request body sent to /scan-sms
data class ScanSmsRequest(
    val sender: String,
    val message: String
)

// Shared verdict schema
data class ScanVerdict(
    val verdict: String,       // "SAFE" | "SUSPICIOUS" | "FRAUD" | "UNKNOWN"
    val confidence: Double,
    val reasons: List<String> = emptyList()
)
