/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>



int main(int argc, char *argv[])

{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char optionPlaintext[100] = "/root/";
	char plaintext[64] = {0,};  //평문 text
	char ciphertext[64] = {0,}; //암호화된 text
	char encryptedkey[1] = {0}; //암호화 키
	char decryptedkey[2] = {0,0}; //복호화 키
	int len = 64;


	res = TEEC_InitializeContext(NULL, &ctx);

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	if(strcmp(argv[1],"-e") == 0){
		printf("========================Encryption========================\n");
		FILE *fp_read_pt = fopen( argv[2],"r");
		fgets(plaintext, sizeof(plaintext), fp_read_pt);  //평문 파일을 읽어 plaintext에 저장
		fclose(fp_read_pt);
		printf("plaintext => %s\n", plaintext);
    //랜덤키 생성
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,  &err_origin);

    //생성한 랜덤키를 이용해 평문을 암호화
		memcpy(op.params[0].tmpref.buffer, plaintext, len); //plaintext의 값을 메모리에 저장
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
    // 에러 핸들링
  	if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

    //TA에서 평문을 암호화한 결과값을 ciphertext에 저장
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("ciphertext => %s\n", ciphertext);

    //암호문을 ciphertext.txt에 저장
		FILE *fp_write_pt = fopen("ciphertext.txt","w");
		fputs(ciphertext, fp_write_pt);
    
		memcpy(op.params[0].tmpref.buffer, encryptedkey, 1);  //encryptedkey초기화
    //랜덤키를 TA의 root key로 암호화
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);

    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

    //TA의 root key로 암호화된 랜덤키를 ciphertext에 이어서 저장
		memcpy(encryptedkey, op.params[0].tmpref.buffer, 1);
		printf("encryptedkey => %c\n", encryptedkey[0]);
		fputc(encryptedkey[0], fp_write_pt);
		fclose(fp_write_pt);

		printf("==========================================================\n");

	}
	else if(strcmp(argv[1],"-d") == 0){

		printf("========================Decryption========================\n");
  //암호문+암호화키 파일 읽기, \n으로 구분되어 암호문과 암호화키가 저장되어있다. 
		FILE *fp_read_cipher_pt = fopen(argv[2],"r");
		fgets(ciphertext, sizeof(ciphertext), fp_read_cipher_pt);
		fgets(decryptedkey, sizeof(decryptedkey), fp_read_cipher_pt);
		printf("ciphertext => %s\n", ciphertext);
		fclose(fp_read_cipher_pt);

    //파일에서 읽은 암호화된 랜덤키를 메모리에 저장
		memcpy(op.params[0].tmpref.buffer, decryptedkey, 1);  
    //TA에서 암호화된 랜덤키를 root키로 복호화
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op, &err_origin);

    //복호화된 랜덤키를 decryptedkey에 저장
		memcpy(decryptedkey, op.params[0].tmpref.buffer, 1);

    //암호문을 메모리에 저장, TA에 암호문 복호화 요청
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", 	res, err_origin);

    //암호문을 복호화해 얻어낸 결과인 평문을 plaintext에저장
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("plaintext => %s", plaintext);

    //복호화한 평문을 파일에 저장
		FILE *fp_write_plain_pt = fopen("plain_result.txt","w");
		fputs(plaintext, fp_write_plain_pt);
		fclose(fp_write_plain_pt);

		printf("===========================================================\n");
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}