package io.github.infarctus.nodauth

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.ReaderException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

object QrDecoder {
    fun decodeBytes(bytes: ByteArray): String {
        require(bytes.size <= 8 * 1024 * 1024)
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return decodeLegacyBmp(bytes)
        var sample = 1
        while (bounds.outWidth / sample > 2048 || bounds.outHeight / sample > 2048) sample *= 2
        val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample })
            ?: return decodeLegacyBmp(bytes)
        return try { decode(bitmap) } finally { bitmap.recycle() }
    }

    private fun decodeLegacyBmp(bytes: ByteArray): String {
        // Microsoft can supply an OS/2 BMP even when the downloaded name is .png.
        require(bytes.size >= 26 && bytes[0] == 0x42.toByte() && bytes[1] == 0x4d.toByte())
        val header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        require(header.getInt(14) == 12 && header.getShort(22).toInt() == 1 && header.getShort(24).toInt() == 24)
        val width = header.getShort(18).toInt() and 0xffff
        val height = header.getShort(20).toInt() and 0xffff
        val offset = header.getInt(10)
        require(width in 1..2048 && height in 1..2048 && offset >= 26)
        val stride = (width * 3 + 3) and -4
        require(offset.toLong() + stride.toLong() * height <= bytes.size)
        val pixels = IntArray(width * height)
        for (y in 0 until height) for (x in 0 until width) {
            val at = offset + (height - y - 1) * stride + x * 3
            val blue = bytes[at].toInt() and 0xff
            val green = bytes[at + 1].toInt() and 0xff
            val red = bytes[at + 2].toInt() and 0xff
            pixels[y * width + x] = (0xff shl 24) or (red shl 16) or (green shl 8) or blue
        }
        return decodePixels(width, height, pixels)
    }

    fun decode(bitmap: Bitmap): String {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        return decodePixels(bitmap.width, bitmap.height, pixels)
    }

    fun decodePixels(width: Int, height: Int, pixels: IntArray): String {
        val image = BinaryBitmap(HybridBinarizer(RGBLuminanceSource(width, height, pixels)))
        return try {
            QRCodeReader().decode(image, mapOf(DecodeHintType.TRY_HARDER to true)).text
        } catch (_: ReaderException) {
            // Downloaded QR images can confuse geometric detection at exact scales.
            // ZXing's pure-code path samples their module grid directly.
            QRCodeReader().decode(image, mapOf(DecodeHintType.PURE_BARCODE to true)).text
        }
    }
}
