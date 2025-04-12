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
    jfieldID utf8_charset_field = env->GetStaticFieldID(standard_charsets_class, "UTF_8", "Ljava/nio/charset/Charset;");
    jobject utf8_charset = env->GetStaticObjectField(standard_charsets_class, utf8_charset_field);

    return utf8_charset;
}

void write_byte_bytebuf(JNIEnv* env, jobject bytebuf, jbyte content) {
    jclass bytebuf_class = env->GetObjectClass(bytebuf);
    jmethodID write_byte_method = env->GetMethodID(bytebuf_class, "writeByte", "(I)Lio/netty/buffer/ByteBuf;");
    env->CallObjectMethod(bytebuf, write_byte_method, content);
}

void write_bytes_bytebuf(JNIEnv* env, jobject bytebuf, jbyteArray content) {
    jclass bytebuf_class = env->GetObjectClass(bytebuf);
    jmethodID write_bytes_method = env->GetMethodID(bytebuf_class, "writeBytes", "([B)Lio/netty/buffer/ByteBuf;");
    env->CallObjectMethod(bytebuf, write_bytes_method, content);
}

void write_int_bytebuf(JNIEnv* env, jobject bytebuf, jint content) {
    jclass bytebuf_class = env->GetObjectClass(bytebuf);
    jmethodID write_int_method = env->GetMethodID(bytebuf_class, "writeInt", "(I)Lio/netty/buffer/ByteBuf;");
    env->CallObjectMethod(bytebuf, write_int_method, content);
}

void write_string_bytebuf(JNIEnv* env, jobject bytebuf, jstring content) {
    jclass bytebuf_class = env->GetObjectClass(bytebuf);
    jmethodID write_charsequence_method = env->GetMethodID(bytebuf_class, "writeCharSequence", "(Ljava/lang/CharSequence;Ljava/nio/charset/Charset;)I");
    env->CallObjectMethod(bytebuf, write_charsequence_method, content, get_utf8_charset(env));
}

void write_int2byte_bytebuf(JNIEnv* env, jobject bytebuf, jint i) {
    while ((i & -128) != 0) {
        write_byte_bytebuf(env, bytebuf, i & 127 | 128);
        i = static_cast<unsigned int>(i) >> 7;
    }

    write_byte_bytebuf(env, bytebuf, i);
}

jobject create_bytebuf(JNIEnv* env) {
    jclass allocator_class = env->FindClass("io/netty/buffer/ByteBufAllocator");

    jfieldID default_allocator_field = env->GetStaticFieldID(allocator_class, "DEFAULT", "Lio/netty/buffer/ByteBufAllocator;");
    jobject default_allocator = env->GetStaticObjectField(allocator_class, default_allocator_field);
    jmethodID buffer_create_method = env->GetMethodID(allocator_class, "buffer", "()Lio/netty/buffer/ByteBuf;");

    
    return env->CallObjectMethod(default_allocator, buffer_create_method);
}

char* make_final_string(std::string motherboard_uuid, std::string platform, std::string signature) {
    std::vector<unsigned char> signature_vector(signature.begin(), signature.end());

    std::vector<unsigned char> motherboard_uuid_vector(motherboard_uuid.begin(), motherboard_uuid.end());
    std::vector<unsigned char> encrypted_motherboard_uuid_vector = aes_encrypt(motherboard_uuid_vector, signature_vector, signature_vector);

    std::vector<unsigned char> platform_vector(platform.begin(), platform.end());
    std::vector<unsigned char> encrypted_platform_vector = aes_encrypt(platform_vector, signature_vector, signature_vector);

    char* encrypted_motherboard_uuid = reinterpret_cast<char*>(encrypted_motherboard_uuid_vector.data());
    char* encrypted_platform = reinterpret_cast<char*>(encrypted_platform_vector.data());

    int result_size = strlen(encrypted_motherboard_uuid) + strlen(encrypted_platform);
    char* result = new char[result_size];
    sprintf(result, "%s,%s", encrypted_motherboard_uuid, encrypted_platform);

    return result;
}

JNIEXPORT jint JNICALL Java_io_github_gdrfgdrf_cuteverification_web_minecraft_client_compatible_DeviceId_send(
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
    char* result = make_final_string(motherboard_uuid, platform, signature);

    jclass channel_outbound_invoker_class = env->FindClass("io/netty/channel/ChannelOutboundInvoker");
    if (channel_outbound_invoker_class == nullptr) {
        return -1;
    }

    jmethodID write_and_flush_method = env->GetMethodID(channel_outbound_invoker_class, "writeAndFlush", "(Ljava/lang/Object;)Lio/netty/channel/ChannelFuture;");
    if (write_and_flush_method == nullptr) {
        return -2;
    }

    size_t length = strlen(result);
    jbyteArray result_jbytearray = env->NewByteArray(length);
    if (result_jbytearray == nullptr) {
        return -3;
    }

    env->SetByteArrayRegion(result_jbytearray, 0, length, reinterpret_cast<const jbyte*>(result));

    if (strcmp(version, "1.14.4") == 0) {
        jobject bytebuf = create_bytebuf(env);

        write_int2byte_bytebuf(env, bytebuf, 56178);
        write_int_bytebuf(env, bytebuf, length);
        write_bytes_bytebuf(env, bytebuf, result_jbytearray);

        env->CallObjectMethod(channel, write_and_flush_method, bytebuf);

        return 0;
    }

    return -4;
}
