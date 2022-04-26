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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>
int root_key;
int randomNumber[10] = {0,};
int randomKey[1] = {0};
char decryptedRandomkey[2] = {0,0};

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}


void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
  //평문을 랜덤키를 이용하여 암호화하는 메소드

	char * in = (char *)params[0].memref.buffer;   //메모리에서 평문 데이터를 가져옴
	int in_len = strlen (params[0].memref.buffer); 
	char encrypted [64]={0,};

  //DMSG은 출력문
	DMSG("========================Encryption========================\n");
	DMSG ("Plaintext :  %s", in);
	memcpy(encrypted, in, in_len);

  //생성한 랜덤키를 이용하여 평문을 암호화
	for(int i=0; i<in_len;i++){
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] -= 'a';
			encrypted[i] += randomKey[0]; 
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += randomKey[0];
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}

	DMSG ("Ciphertext :  %s", encrypted);
	memcpy(in, encrypted, in_len);  //메모리에 랜덤키를 이용하여 안호화한 암호문을 저장

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
  //랜덤키를 이용하여 평문으로 복호화하는 메소드
	char * in = (char *)params[0].memref.buffer;  //암호문 전달
	int in_len = strlen (params[0].memref.buffer);
	char decrypted[64]={0,}; 
	memcpy(decrypted, in, in_len);
	DMSG("========================Decryption========================\n");
	DMSG ("Ciphertext :  %s", in);
	DMSG ("randomKey :  %s", randomKey[0]);
	DMSG ("in is :  %s", in);


  //복호화된 랜덤키를 이용하여 암호문을 복호화 => 평문
	for(int i=0; i<in_len;i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] -= 'a';
			decrypted[i] -= decryptedRandomkey[0];
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= decryptedRandomkey[0];
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}

	DMSG ("Plaintext :  %s", decrypted);
	memcpy(in, decrypted, in_len);  //메모리에 복호화된 평문 결과값을 저장

	return TEE_SUCCESS;
}

static TEE_Result randomkey_get()
{
  //랜덤키 생성 메소드
	do{
		TEE_GenerateRandom(randomNumber, sizeof(randomNumber));
	} while(randomNumber[0] <= 0);

	randomKey[0] = randomNumber[0] % 25 + 1;  //1~25사이의 랜덤키를 생성
	
	DMSG("=====================Get RandomKey=====================\n");
	DMSG ("random key =>  %d\n", randomKey[0]);

	return TEE_SUCCESS;

}

static TEE_Result randomkey_enc(uint32_t param_types,
	TEE_Param params[4])
{
  //랜덤키를 root key를 이용해 암호화하는 메소드
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	char * in = (char *)params[0].memref.buffer;  
	int in_len = strlen (params[0].memref.buffer);

	char encryptedRandomkey[1]={0};

	DMSG("===================Encryption RandomKey===================\n");
	DMSG ("rootkey =>  %d\n", root_key);
	DMSG ("randomkey =>   %d\n", randomKey[0]);

	encryptedRandomkey[0] = 'A' + randomKey[0];
	DMSG("alphabet =>  %c\n", encryptedRandomkey[0]);

  //root key를 이용하여 random key를 암호화
	if (encryptedRandomkey[0] >= 'A' && encryptedRandomkey[0] <= 'Z') {
			encryptedRandomkey[0] -= 'A';
			encryptedRandomkey[0] += root_key;
			encryptedRandomkey[0] = encryptedRandomkey[0] % 26;
			encryptedRandomkey[0] += 'A';
		}

	DMSG("encrypted ==>  %c\n", encryptedRandomkey[0]);
	
  //암호화된 random key를 메모리에 저장
	memcpy(in, encryptedRandomkey, 1);
	return TEE_SUCCESS;
}

static TEE_Result randomkey_dec(uint32_t param_types,
	TEE_Param params[4])
{
  //암호화된 랜덤키를 root key로 복호화하는 메소드

	char * in = (char *)params[0].memref.buffer;  //암호화된 랜덤키 정보
	memcpy(decryptedRandomkey, in, 1);

	DMSG("===================Decryption RandomKey===================\n");
	DMSG ("decryptedRandomkey is :  %s", decryptedRandomkey);
  //root를 이용하여 복호화
	if (decryptedRandomkey[0] >= 'A' && decryptedRandomkey[0] <= 'Z') {
			decryptedRandomkey[0] -= 'A';
			decryptedRandomkey[0] -= root_key;
			decryptedRandomkey[0] += 26;
			decryptedRandomkey[0] = decryptedRandomkey[0] % 26;
			
		}

  //복호화한 랜덤키를 메소드에 저장
	memcpy(in, decryptedRandomkey, 1);  
	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	root_key = 25;

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_GET:
		return randomkey_get();
	case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
		return randomkey_enc(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_DEC:
		return randomkey_dec(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
