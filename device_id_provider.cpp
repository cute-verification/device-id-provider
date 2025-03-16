#pragma execution_character_set("utf-8")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#include "io_github_gdrfgdrf_cuteverification_web_minecraft_client_impl_fabric_natives_DeviceId.h"
#include <iostream>
#include <fstream>
#include "openssl/ssl.h"
#include <vector>

const int CUSTOM_PACKET_ID = 56178;

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

jobject get_utf8_charset(JNIEnv* env) {
    jclass standard_charsets_class = env->FindClass("java/nio/charset/StandardCharsets");
    jfieldID utf8_charset_field = env->GetStaticFieldID(standard_charsets_class, "UTF-8", "Ljava/nio/charset/Charset;");
    jobject utf8_charset = env->GetStaticObjectField(standard_charsets_class, utf8_charset_field);

    return utf8_charset;
}

void write_byte_bytebuf(JNIEnv* env, jobject bytebuf, jint content) {
    jclass bytebuf_class = env->GetObjectClass(bytebuf);
    jmethodID write_byte_method = env->GetMethodID(bytebuf_class, "writeByte", "(I)Lio/netty/buffer/ByteBuf;");
    env->CallObjectMethod(bytebuf, write_byte_method, content);
}

void write_string_bytebuf(JNIEnv* env, jobject bytebuf, jstring content) {
    jclass bytebuf_class = env->GetObjectClass(bytebuf);
    jmethodID write_charsequence_method = env->GetMethodID(bytebuf_class, "writeCharSequence", "(Ljava/lang/CharSequence;Ljava/nio/charset/Charset;)I");
    env->CallObjectMethod(bytebuf, write_charsequence_method, content, get_utf8_charset(env));
}

jobject create_bytebuf(JNIEnv* env, int length) {
    jclass allocator_class = env->FindClass("io/netty/buffer/ByteBufAllocator");
    jclass byteBuf_class = env->FindClass("io/netty/buffer/ByteBuf");

    jmethodID default_allocator_method = env->GetStaticMethodID(allocator_class, "DEFAULT", "()Lio/netty/buffer/ByteBufAllocator;");
    jobject default_allocator = env->CallStaticObjectMethod(allocator_class, default_allocator_method);
    jmethodID buffer_create_method = env->GetMethodID(allocator_class, "buffer", "(I)Lio/netty/buffer/ByteBuf;");

    
    return env->CallObjectMethod(default_allocator, buffer_create_method, length);
}

JNIEXPORT void JNICALL Java_io_github_gdrfgdrf_cuteverification_web_minecraft_client_impl_fabric_natives_DeviceId_send(
    JNIEnv* env,
    jclass,
    jstring platform_jstring,
    jstring signature_jstring,
    jstring version_jstring,
    jobject channel) {
    char* platform = jstring2char(env, platform_jstring);
    char* signature = jstring2char(env, signature_jstring);
    char* version = jstring2char(env, version_jstring);

    std::string motherboard_uuid = get_windows_motherboard_uuid();
    if (motherboard_uuid == "") {
		return;
    }

    std::vector<unsigned char> result_(motherboard_uuid.begin(), motherboard_uuid.end());
    std::vector<unsigned char> signature_ = string2bytes(signature, 16);
    std::vector<unsigned char> encrypted_result = aes_encrypt(result_, signature_, signature_);

    char* result = reinterpret_cast<char*>(encrypted_result.data());

    jclass channel_class = env->GetObjectClass(channel);
    if (channel_class == nullptr) {
        return;
    }

    jmethodID write_and_flush_method = env->GetMethodID(channel_class, "writeAndFlush", "(Ljava/lang/Object;)Lio/netty/channel/ChannelFuture;");
    if (write_and_flush_method == nullptr) {
        return;
    }

    jstring j_result = char2jstring(env, result);
    

    if (strcmp(version, "1.14.4")) {
        jsize j_result_length = env->GetStringLength(j_result);
        jobject bytebuf = create_bytebuf(env, j_result_length + 4);

        write_byte_bytebuf(env, bytebuf, CUSTOM_PACKET_ID);
        write_byte_bytebuf(env, bytebuf, j_result_length);
        write_string_bytebuf(env, bytebuf, j_result);

        env->CallObjectMethod(channel, write_and_flush_method, bytebuf);
    }

    return;
}

