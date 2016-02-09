#include "stdafx.h"

int main()
{
    DWORD status = 0;
    NCRYPT_PROV_HANDLE hProv = NULL;
    PBYTE pbEkPub = NULL;
    DWORD cbEkPub = 0;
    BCRYPT_RSAKEY_BLOB* pKey = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE pbHashObject = NULL;
    DWORD cbHashObject = 0, cbData = 0;
    BYTE rgbHash[32] = { 0 };
    LPWSTR wszHash = NULL;
    DWORD cchHash = 0;

    //
    // Open a handle to the Microsoft Platform KSP
    //

    if (0 != (status = NCryptOpenStorageProvider(
        &hProv,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0)))
    {
        goto Cleanup;
    }

    //
    // Read out the public components of the Trusted Platform Module (TPM) 
    // Endorsement Key (EK), if any
    //

    if (0 != (status = NCryptGetProperty(
        hProv,
        NCRYPT_PCP_EKPUB_PROPERTY,
        NULL,
        0,
        &cbEkPub,
        0)))
    {
        goto Cleanup;
    }

    if (NULL == (pbEkPub = (PBYTE)malloc(cbEkPub)))
    {
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }

    if (0 != (status = NCryptGetProperty(
        hProv,
        NCRYPT_PCP_EKPUB_PROPERTY,
        pbEkPub,
        cbEkPub,
        &cbEkPub,
        0)))
    {
        goto Cleanup;
    }

    pKey = (BCRYPT_RSAKEY_BLOB*)pbEkPub;

    //
    // Open a hash handle
    //

    if (0 != (status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0)))
    {
        goto Cleanup;
    }

    if (0 != (status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        goto Cleanup;
    }

    if (NULL == (pbHashObject = (PBYTE) malloc(cbHashObject)))
    {
        goto Cleanup;
    }

    if (0 != (status = BCryptCreateHash(
        hAlg,
        &hHash,
        pbHashObject,
        cbHashObject,
        NULL,
        0,
        0)))
    {
        goto Cleanup;
    }

    //
    // Hash the public key
    //

    if (0 != (status = BCryptHashData(
        hHash,
        &pbEkPub[sizeof(BCRYPT_RSAKEY_BLOB) + pKey->cbPublicExp],
        pKey->cbModulus, 
        0)))
    {
        goto Cleanup;
    }

    if (0 != (status = BCryptFinishHash(
        hHash,
        rgbHash,
        sizeof(rgbHash),
        0)))
    {
        goto Cleanup;
    }

    //
    // Convert bytes to string
    //

    if (FALSE == CryptBinaryToStringW(
        rgbHash,
        sizeof(rgbHash),
        CRYPT_STRING_HEXRAW,
        NULL,
        &cchHash))
    {
        status = GetLastError();
        goto Cleanup;
    }

    if (NULL == (wszHash = (LPWSTR)malloc(sizeof(WCHAR) * (1 + cchHash))))
    {
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }

    if (FALSE == CryptBinaryToStringW(
        rgbHash,
        sizeof(rgbHash),
        CRYPT_STRING_HEXRAW,
        wszHash,
        &cchHash))
    {
        status = GetLastError();
        goto Cleanup;
    }

    //
    // Display to console
    //

    printf("%S", wszHash);

Cleanup:
    if (0 != status)
        printf("Error: 0x%x\n", status);
    if (NULL != pbEkPub)
        free(pbEkPub);
    if (NULL != wszHash)
        free(wszHash);
    if (NULL != hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    if (NULL != pbHashObject)
        free(pbHashObject);

    return (int) status;
}