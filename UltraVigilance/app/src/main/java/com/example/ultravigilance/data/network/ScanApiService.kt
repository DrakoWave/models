package com.example.ultravigilance.data.network

import com.example.ultravigilance.data.model.ScanDocumentRequest
import com.example.ultravigilance.data.model.ScanDocumentResponse
import com.example.ultravigilance.data.model.ScanSmsRequest
import com.example.ultravigilance.data.model.ScanVerdict
import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST

interface ScanApiService {
    @POST("scan-document")
    suspend fun scanDocument(@Body request: ScanDocumentRequest): Response<ScanDocumentResponse>

    @POST("scan-sms")
    suspend fun scanSms(@Body request: ScanSmsRequest): Response<ScanVerdict>
}

object ScanApiClient {
    // Live FastAPI backend tunnel
    private const val BASE_URL = "https://grandly-nonmathematic-elwanda.ngrok-free.dev/"

    private val okHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .addInterceptor { chain ->
            val request = chain.request().newBuilder()
                .addHeader("ngrok-skip-browser-warning", "true")
                .addHeader("User-Agent", "UltraVigilance-Android")
                .build()
            chain.proceed(request)
        }
        .build()

    val api: ScanApiService by lazy {
        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(ScanApiService::class.java)
    }
}
