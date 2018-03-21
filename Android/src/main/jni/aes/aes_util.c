//
// Created by J!nl!n on 15/12/21.
//

#include "com_example_mohsinmustafa1_aesndk_aes_AES.h"
#include <stdio.h>
#include <stdlib.h>
#include "aes.h"

//CRYPT CONFIG
#define MAX_LEN (2*1024*1024)
#define ENCRYPT 0
#define DECRYPT 1
#define AES_KEY_SIZE 128
#define READ_LEN 10

#define TARGET_CLASS "com/example/mohsinmustafa1/aesndk/Helper/AES"
#define TARGET_CRYPT "crypt"
#define TARGET_CRYPT_SIG "([BJI)[B"
#define TARGET_READ "read"
#define TARGET_READ_SIG "(Ljava/lang/String;J)[B"

//AES_IV
static unsigned char AES_IV[16] = { 0x74 ,0x68 ,0x69 ,0x73 ,0x20 ,0x69 ,0x74 ,0x20 ,0x74 ,0x68 ,0x65 ,0x20 ,0x6b ,0x65 ,0x79 ,0x2e };
//AES_KEY
/*static unsigned char AES_KEY[32] = { 0x62 ,0x72 ,0x65 ,0x61 ,0x6b ,0x6d ,0x65 ,0x69 ,0x66 ,
                                     0x75 ,0x63 ,0x61 ,0x6e ,0x62 ,0x62 ,0x79 ,0x62 ,0x72 ,
                                     0x65 ,0x61 ,0x6b ,0x6d ,0x65 ,0x69 ,0x66 ,0x75 ,0x63 ,
                                     0x61 ,0x6e ,0x62 ,0x62 ,0x79 };*/
                                    //Key = this it the key.
static unsigned char AES_KEY[16] = { 0x74 ,0x68 ,0x69 ,0x73 ,0x20 ,0x69 ,0x74 ,0x20 ,0x74 ,0x68 ,0x65 ,0x20 ,0x6b ,0x65 ,0x79 ,0x2e };

/*
 * Class:     tv_fun_common_crypt_Funcrypt
 * Method:    sha1
 * Signature: (Ljava/lang/String;JI)[Ljava/lang/Object;
 */
JNIEXPORT jbyteArray JNICALL android_native_aes(JNIEnv *env, jclass clazz,
                                                jbyteArray jarray, jlong jtimestamp, jint jmode) {
    //check input data
    unsigned int len = (unsigned int) ((*env)->GetArrayLength(env, jarray));
    if (len <= 0 || len >= MAX_LEN) {
        return NULL;
    }

    unsigned char *data = (unsigned char*) (*env)->GetByteArrayElements(env,
                                                                        jarray, NULL);
    if (!data) {
        return NULL;
    }

    unsigned int mode = (unsigned int) jmode;
    unsigned int rest_len = len % AES_BLOCK_SIZE;
    unsigned int padding_len = (
            (ENCRYPT == mode) ? (AES_BLOCK_SIZE - rest_len) : 0);
    unsigned int src_len = len + padding_len;

    unsigned char *input = (unsigned char *) malloc(src_len);
    memset(input, 0, src_len);
    memcpy(input, data, len);
    if (padding_len > 0) {
        memset(input + len, (unsigned char) padding_len, padding_len);
    }

    (*env)->ReleaseByteArrayElements(env, jarray, data, 0);

    unsigned char * buff = (unsigned char*) malloc(src_len);
    if (!buff) {
        free(input);
        return NULL;
    }
    memset(buff, src_len, 0);

    //set key & iv
    unsigned int key_schedule[AES_BLOCK_SIZE * 4] = { 0 };
    aes_key_setup(AES_KEY, key_schedule, AES_KEY_SIZE);

    if (mode == ENCRYPT) {
        aes_encrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE,
                        AES_IV);
    } else {
        aes_decrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE,
                        AES_IV);
    }

    if (ENCRYPT != mode) {
        unsigned char * ptr = buff;
        ptr += (src_len - 1);
        padding_len = (unsigned int) *ptr;
        if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
            src_len -= padding_len;
        }
        ptr = NULL;
    }

    jbyteArray bytes = (*env)->NewByteArray(env, src_len);
    (*env)->SetByteArrayRegion(env, bytes, 0, src_len, (jbyte*) buff);

    free(input);
    free(buff);

    return bytes;
}

JNIEXPORT jbyteArray JNICALL android_native_read(JNIEnv *env, jclass clazz,
                                                 jstring jstr, jlong jtimestam) {
    char * path = (char *) (*env)->GetStringUTFChars(env, jstr, NULL);
    if (!path) {
        return NULL;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }
    (*env)->ReleaseStringUTFChars(env, jstr, path);

    char pBuf[READ_LEN + 1] = { 0 };
    fread(pBuf, 1, READ_LEN, fp);
    pBuf[READ_LEN] = 0;
    fclose(fp);

    jbyteArray bytes = (*env)->NewByteArray(env, READ_LEN);
    (*env)->SetByteArrayRegion(env, bytes, 0, READ_LEN, (jbyte*) pBuf);

    return bytes;
}

static const JNINativeMethod gMethods[] = { { TARGET_CRYPT, TARGET_CRYPT_SIG,
                                                    (void*) android_native_aes }, { TARGET_READ, TARGET_READ_SIG,
                                                    (void*) android_native_read } };

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env = NULL;
    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_4) != JNI_OK) {
        return -1;
    }

    jclass clazz = (*env)->FindClass(env, TARGET_CLASS);
    if (!clazz) {
        return -1;
    }

    if ((*env)->RegisterNatives(env, clazz, gMethods,
                                sizeof(gMethods) / sizeof(gMethods[0])) != JNI_OK) {
        return -1;
    }

    return JNI_VERSION_1_4;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved) {
    JNIEnv* env = NULL;
    if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_4) != JNI_OK) {
        return;
    }
}
