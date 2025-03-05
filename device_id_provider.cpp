#pragma execution_character_set("utf-8")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#include "io_github_gdrfgdrf_cuteverification_web_minecraft_client_impl_fabric_natives_DeviceId.h"
#include <iostream>
#include <fstream>
#include "openssl/ssl.h"
#include <vector>

std::vector<BYTE> get_smbios_data() {
    DWORD bufferSize = 0;
    bufferSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (bufferSize == 0) {
        return {};
    }

    std::vector<BYTE> buffer(bufferSize);
    if (GetSystemFirmwareTable('RSMB', 0, buffer.data(), bufferSize) != bufferSize) {
        return {};
    }

    return buffer;
}

std::string get_windows_motherboard_uuid() {
    std::vector<BYTE> smbios_data = get_smbios_data();
    if (smbios_data.empty()) {
        return "";
    }

    const BYTE* data = smbios_data.data();
    DWORD table_length = *(DWORD*)(data + 0x04);
    const BYTE* table_data = data + 0x08;

    const BYTE* end = table_data + table_length;
    while (table_data + 4 <= end) {
        BYTE type = table_data[0];
        BYTE length = table_data[1];

        if (type == 1 && length >= 0x19) {
            const BYTE* uuid_ptr = table_data + 0x08;
            char uuid[37];
            snprintf(
                uuid, sizeof(uuid),
                "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                uuid_ptr[0], uuid_ptr[1], uuid_ptr[2], uuid_ptr[3],
                uuid_ptr[4], uuid_ptr[5], uuid_ptr[6], uuid_ptr[7],
                uuid_ptr[8], uuid_ptr[9], uuid_ptr[10], uuid_ptr[11],
                uuid_ptr[12], uuid_ptr[13], uuid_ptr[14], uuid_ptr[15]
            );
            return uuid;
        }

        table_data += length;
        while (table_data < end && (table_data[0] != 0 || table_data[1] != 0)) {
            table_data++;
        }
        table_data += 2;
    }

    return "";
}

//std::string get_linux_motherboard_uuid() {
//    std::ifstream uuid_file("/sys/class/dmi/id/product_uuid");
//    if (!uuid_file.is_open()) {
//        return "";
//    }
//
//    std::string uuid;
//    std::getline(uuid_file, uuid);
//    uuid_file.close();
//
//    if (!uuid.empty() && uuid.back() == '\n') {
//        uuid.pop_back();
//    }
//
//    return uuid;
//}

char* jstring2char(JNIEnv* env, jstring jstr) {
    int length = (env)->GetStringLength(jstr);
    const jchar* jcstr = (env)->GetStringChars(jstr, 0);
    char* rtn = (char*)malloc(length * 2 + 1);
    int size = 0;
    size = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)jcstr, length, rtn,
        (length * 2 + 1), NULL, NULL);
    if (size <= 0)
        return NULL;
    (env)->ReleaseStringChars(jstr, jcstr);
    rtn[size] = 0;
    return rtn;
}

jstring char2jstring(JNIEnv* env, const char* str) {
    jstring rtn = 0;
    int slen = strlen(str);
    unsigned short* buffer = 0;
    if (slen == 0)
        rtn = (env)->NewStringUTF(str);
    else {
        int length = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)str, slen, NULL, 0);
        buffer = (unsigned short*)malloc(length * 2 + 1);
        if (MultiByteToWideChar(CP_ACP, 0, (LPCSTR)str, slen, (LPWSTR)buffer, length) > 0)
            rtn = (env)->NewString((jchar*)buffer, length);
        free(buffer);
    }
    return rtn;
}

std::vector<unsigned char> string2bytes(const std::string& str, size_t required_length) {
    std::vector<unsigned char> bytes(required_length, 0);
    size_t length = (((str.size()) < (required_length)) ? (str.size()) : (required_length));
    memcpy(bytes.data(), str.data(), length);
    return bytes;
}

std::vector<unsigned char> aes_encrypt(
    const std::vector<unsigned char>& raw_content,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::runtime_error("Key must be 128, 192, or 256 bits long!");
    }
    if (iv.size() != 16) {
        throw std::runtime_error("IV must be 128 bits long!");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX!");
    }

    int ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb8(), nullptr, key.data(), iv.data());
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption!");
    }

    std::vector<unsigned char> encrypted_content(raw_content.size() + EVP_MAX_BLOCK_LENGTH);
    int length;
    int encrypted_content_length = 0;

    ret = EVP_EncryptUpdate(ctx, encrypted_content.data(), &length, raw_content.data(), raw_content.size());
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed!");
    }
    encrypted_content_length += length;

    ret = EVP_EncryptFinal_ex(ctx, encrypted_content.data() + encrypted_content_length, &length);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Final encryption failed!");
    }
    encrypted_content_length += length;

    EVP_CIPHER_CTX_free(ctx);

    encrypted_content.resize(encrypted_content_length);
    return encrypted_content;
}

std::vector<unsigned char> aes_decrypt(
    const std::vector<unsigned char>& encrypted_content,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::runtime_error("Key must be 128, 192, or 256 bits long!");
    }
    if (iv.size() != 16) {
        throw std::runtime_error("IV must be 128 bits long!");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX!");
    }

    int ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb8(), nullptr, key.data(), iv.data());
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption!");
    }

    std::vector<unsigned char> decrypted_content(encrypted_content.size() + EVP_MAX_BLOCK_LENGTH);
    int length;
    int decrypted_content_length = 0;

    ret = EVP_DecryptUpdate(ctx, decrypted_content.data(), &length, encrypted_content.data(), encrypted_content.size());
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed!");
    }
    decrypted_content_length += length;

    ret = EVP_DecryptFinal_ex(ctx, decrypted_content.data() + decrypted_content_length, &length);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Final decryption failed!");
    }
    decrypted_content_length += length;

    EVP_CIPHER_CTX_free(ctx);

    decrypted_content.resize(decrypted_content_length);
    return decrypted_content;
}

JNIEXPORT jstring JNICALL Java_io_github_gdrfgdrf_cuteverification_web_minecraft_client_impl_fabric_natives_DeviceId_get(
    JNIEnv* env,
    jclass,
    jstring platform_jstring,
    jstring signature_jstring) {
    char* platform = jstring2char(env, platform_jstring);
    char* signature = jstring2char(env, signature_jstring);
    std::string result = get_windows_motherboard_uuid();
    if (result == "") {
		return char2jstring(env, "");
    }

    std::vector<unsigned char> result_(result.begin(), result.end());
    std::vector<unsigned char> signature_ = string2bytes(signature, 16);
    std::vector<unsigned char> encrypted_result = aes_encrypt(result_, signature_, signature_);

    char* final_result = reinterpret_cast<char*>(encrypted_result.data());

    return char2jstring(env, final_result);
}