package com.example.immutablestorageforjpki

import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Base64
import android.util.Log
import org.json.JSONObject

@ExperimentalUnsignedTypes
class HndIsoDep(
    private val tag: Tag
){
    private fun isoDepSelectDF(id: String): ByteArray {
        val idRaw = id.chunked(2).map{it.toInt(16).toByte()}.toByteArray()

        var rawData: ByteArray = ubyteArrayOf(
            0x00u, // CLA, class
            0xA4u, // INS: select command
            0x04u, // P1: select by DF names
            0x0Cu, // P2: response data field requirements, proprietary
            idRaw.size.toUByte() // Lc: length
        ).toByteArray()
        rawData += idRaw
        return rawData
    }

    private fun isoDepSelectEF(id: String): ByteArray {
        val rawData = isoDepSelectDF(id)
        rawData[2] = 0x02 // P1: select EF under the current DF
        return rawData
    }

    private fun isoDepPerformSecurityOp(src: ByteArray): ByteArray {
        var rawData: ByteArray = ubyteArrayOf(
            0x80u, // CLS, the proprietary class
            0x2Au, // INS: perform security operation command
            0x00u, // P1: (expected response data field), ignore?
            0x80u, // P2: command data field, plain value not encoded in BER-TLV
            src.size.toUByte() // Lc
        ).toByteArray()

        rawData += src
        rawData += 0 // Le
        return rawData
    }

    private fun isoDepReadBinary(offset: Int, size :Int): ByteArray {
        return ubyteArrayOf(
            0x00u, // CLA, class
            0xB0u, // INS: read binary command
            (offset.shr(8) and 0xff).toUByte(), // P1: high offset
            (offset and 0xff).toUByte(), // P2: low offset
            size.toUByte() // Lc:
        ).toByteArray()
    }

    private fun isoDepVerifyData(data: String): ByteArray {
        var rawData: ByteArray = ubyteArrayOf(
            0x00u, // CLA, class
            0x20u, // INS, verify command; verification data or absent
            0x00u, // P1, normal operation
            0x80u, // P2, coding of the reference data qualifier PIN
            data.length.toUByte() // Lc field
        ).toByteArray()
        rawData += data.toByteArray()

        return rawData
    }


    private fun getErrorMsg(rsp: ByteArray): String {
        if (rsp.size < 2) {
            return "unexpected response"
        }

        return getErrorMsg(rsp[rsp.size-2].toUByte().toInt(), rsp[rsp.size-1].toUByte().toInt())
    }

    private fun getErrorMsg(SW1: Int, SW2: Int): String {
        if ( (SW1 == 0x90) && (SW2 == 0x00) ) {
            return "" // success
        }

        when(SW1) {
            0x62 -> {
                when(SW2) {
                    0x83 -> return "Selected file deactivated"
                    0x85 -> return "Selected file in termination state"
                }
            }
            0x69 -> {
                when(SW2) {
                    0x86 -> return "error: command not allowed"
                }
            }
            0x6a -> {
                when(SW2) {
                    0x00 -> return "error: no information"
                    0x80 -> return "error: incorrect parameters in data"
                    0x81 -> return "error: function not supported"
                    0x82 -> return "error: file or application not found"
                    0x84 -> return "error: not enough memory"
                    0x85 -> return "error: Nc inconsistent with TLV structure"
                    0x86 -> return "error: incorrect parameters in P1 or P2"
                    0x87 -> return "error: Nc inconsistent with P1 or P2"
                    0x88 -> return "error: reference data not found"
                    0x89 -> return "error: file already exists"
                    0x8a -> return "error: DF name already exists"
                }
            }
        }
        return "unknown error: SW1=0x%02x, SW2=0x%02x".format(SW1, SW2)
    }

    private fun IsoDep.readBinary(size: Int): ByteArray {
        var rsp: ByteArray
        var readRaw: ByteArray = byteArrayOf()
        var offset = 0

        while(offset < size) {
            rsp = this.transceive(isoDepReadBinary(offset, size-offset))
            val errMsg = getErrorMsg(rsp)
            if (errMsg != "") {
                throw Exception("readBinary: $errMsg")
            }

            readRaw += rsp.copyOf(rsp.size-2)
            offset = readRaw.size
        }

        return readRaw // success
    }

    private fun IsoDep.selectDF(aid: String) {
        val rsp = this.transceive(isoDepSelectDF(aid))
        val err = getErrorMsg(rsp)
        if (err != "") {
            throw Exception("selectDF: $err")
        }
    }

    private fun IsoDep.selectEF(id: String) {
        val rsp = this.transceive(isoDepSelectEF(id))
        val err = getErrorMsg(rsp)
        if (err != "" ){
            throw Exception("selectEF: $err")
        }
    }

    private fun IsoDep.readCertificate(id: String): ByteArray {
        this.selectEF(id)
        var certRaw = this.readBinary(9)

        val tagAndLen = certRaw // get ANS1 tag and length
        var tag = tagAndLen[0].toUByte().toLong() and 0x1fL // add code here
        var offset = 1
        var tmp = tagAndLen[offset].toUByte().toLong()

        if ( (tag == 0x1fL) && (tmp == 0x80L) ) {
            throw Exception("readCertificate: unexpected data") // error
        }

        if ( tag == 0x1fL ) {
            for(i in 1..5) {
                if (i == 5) {
                    throw Exception("readCertificate: unexpected tag in data") // error
                }
                tag = tag.shl(7)
                tag = tag.or(tmp and 0x7fL)

                offset++
                if (tmp.and(0x80L) == 0L) {
                    if (tag > Int.MAX_VALUE) {
                        throw Exception("readCertificate: too large for a tag") // error
                    }
                    break
                }
                tmp = tagAndLen[offset].toLong()
            }
        }
        // max offset = 5
        val tmpLen = tagAndLen[offset].toUByte().toInt()
        var len = 0
        offset++

        if (tmpLen.and(0x80) == 0) {
            len = tmpLen.and(0x7f)
        } else {
            val n = tmpLen.and(0x7f)
            if ( (n == 0) || (n > 4) ){
                throw Exception("readCertificate: unexpected length") // error
            }

            for (i in 0 until n) {
                val lenByte = tagAndLen[offset].toUByte().toInt()
                offset++

                if ( len >= 1.shl(23) ) {
                    throw Exception("readCertificate: length too large") // error
                }

                len = len.shl(8)
                len = len.or(lenByte)
            }
            if (len < 0x80) {
                throw Exception("readCertificate: incorrect data") // error
            }
        }

        certRaw = this.readBinary(offset+len)
        return certRaw // success
    }

    private fun IsoDep.selectJPKIAP() {
        this.selectDF("D392F000260100000001")
    }

    private fun IsoDep.readJPKICert(id: String, pin: String = ""): ByteArray {
        this.selectJPKIAP()

        if (pin != "") {
            this.verifySignPIN(pin)
        }
        return this.readCertificate(id)
    }


    private fun IsoDep.verifyData(data: String) {
        val rsp = this.transceive(isoDepVerifyData(data))
        if (rsp.size != 2) {
            throw Exception("verifyData: unexpected response")
        }

        val SW1 = rsp[0].toUByte().toInt()
        val SW2 = rsp[1].toUByte().toInt()
        if ( (SW1 == 0x90) && (SW2 == 0x00) ) {
            return // success
        }

        if (SW1 == 0x63) {
            when(SW2){
                0x00 ->
                    throw Exception("verifyData: the verification failed")
                in 0xC0..0xCF ->
                    throw Exception("verifyData: the number of attempts to verify data: %d".format(SW2.and(0xf)))
            }
        }

        if ( (SW1 == 0x6A) && (SW2 == 0x88) ) {
            throw Exception("verifyData: reference data not found")
        }

        val err = getErrorMsg(SW1, SW2)
        if (err != "") {
            throw Exception("verifyData: $err")
        }
    }

    private fun IsoDep.verifySignPIN(pin: String) {
        this.selectEF("001B")
        this.verifyData(pin)
    }

    private fun IsoDep.verifyAuthPIN(pin: String) {
        this.selectEF("0018")
        this.verifyData(pin)
    }

    private fun IsoDep.performSecurityOp(src: ByteArray): ByteArray {
        val rsp = this.transceive(isoDepPerformSecurityOp(src))

        val err = getErrorMsg(rsp)
        if (err != "") {
            throw Exception("performSecurityOp: $err")
        }

        return rsp.copyOf(rsp.size-2) // success
    }

    private fun IsoDep.signData(pin: String, raw: ByteArray): ByteArray {
        this.selectJPKIAP()
        this.verifySignPIN(pin)
        this.selectEF("001A")
        return this.performSecurityOp(raw)
    }

    private fun IsoDep.signDataUsingAuthKey(pin: String, raw: ByteArray): ByteArray {
        this.selectJPKIAP()
        this.verifyAuthPIN(pin)
        this.selectEF("0017")
        return this.performSecurityOp(raw)
    }

    private fun IsoDep.getJPKIToken(): ByteArray {
        this.selectJPKIAP()
        this.selectEF("0006")
        return this.readBinary(0x20) // read 32 characters
    }

    fun isJPKI(): Boolean {
        IsoDep.get(tag)?.use{
            try {
                it.connect()
                val token = it.getJPKIToken()
                val tokenStr = token.toString(Charsets.US_ASCII).trimEnd()
                return ( tokenStr == "JPKIAPICCTOKEN2" )
            }catch(e: java.io.IOException) {
            }catch(e: Exception) {
                Log.i("isJPKI: ", e.toString() )
            }
        }
        return false
    }

    fun readCert(certFun: (IsoDep) -> ByteArray ): String {
        var certData = ""
        var err = ""

        IsoDep.get(tag)?.use {
            try{
                it.connect()
                val cert = certFun(it)
                Log.i("readCert", "len=%d".format(cert.size))
                certData = Base64.encodeToString(cert, Base64.DEFAULT)
                Log.i("readCert", certData)
            }catch(e: java.io.IOException) {
                err = e.toString()
            }catch(e: Exception) {
                err = e.toString()
            }
        }

        val retJSON = JSONObject()
        retJSON.put("cert", certData)
        retJSON.put("err", err)
        return retJSON.toString()
    }

    fun readAuthCert(): String {
        return readCert { it.readJPKICert("000A") }
    }
    fun readAuthCACert(): String {
        return readCert { it.readJPKICert("000B") }
    }
    fun readSignCert(pin: String): String {
        return readCert { it.readJPKICert("0001", pin) }
    }
    fun readSignCACert(): String {
        return readCert { it.readJPKICert("0002") }
    }

    fun signData(raw: String, signFunc: (IsoDep, ByteArray) -> ByteArray): String {
        val rawBase64 = Base64.decode(raw, Base64.DEFAULT)
        var signBase64 = ""
        var err = ""

        IsoDep.get(tag)?.use {
            try {
                it.connect()
                val signature = signFunc(it, rawBase64)
                signBase64 = Base64.encodeToString(signature, Base64.DEFAULT)
            } catch (e: java.io.IOException) {
                err = e.toString()
            } catch (e: Exception) {
                err = e.toString()
            }
        }

        val retJSON = JSONObject()
        retJSON.put("signature", signBase64)
        retJSON.put("err", err)

        return retJSON.toString()
    }

    fun signRawData(pin: String, raw: String): String {
        return signData(raw) { isoDep: IsoDep, rawB64: ByteArray ->
            isoDep.signData(pin, rawB64)
        }
    }

    fun signRawDataUsingAuthKey(pin: String, raw: String): String {
        return signData(raw) { isoDep: IsoDep, rawB64: ByteArray ->
            isoDep.signDataUsingAuthKey(pin, rawB64)
        }
    }

    fun handleIsoDep(): String {
        // NFC type A or B
        var msg = ""

        IsoDep.get(tag)?.use { isoDep ->
            try {
                isoDep.connect()
                msg += "hi layer: " + isoDep.hiLayerResponse?.joinToString {
                    "%02x".format(it)
                }
                msg += "\n"
            }catch(e: java.io.IOException){
                msg += "got error: " + e.toString() + "\n"
            }
        }

        return msg
    }
}