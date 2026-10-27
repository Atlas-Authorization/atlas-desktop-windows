#pragma once
#include <guiddef.h>

// CLSID of the Atlas wrapping credential provider.
// {C3B1A0E6-6D1F-4B0E-9C57-2F1B7A9D4E58}
static const GUID CLSID_AtlasCredentialProvider = {0xc3b1a0e6, 0x6d1f, 0x4b0e, {0x9c, 0x57, 0x2f, 0x1b, 0x7a, 0x9d, 0x4e, 0x58}};
// The stock Windows password provider that this DLL wraps.
// {60b78e88-ead8-445c-9cfd-0b87f74ea6cd}
static const GUID CLSID_StockPasswordProvider = {0x60b78e88, 0xead8, 0x445c, {0x9c, 0xfd, 0x0b, 0x87, 0xf7, 0x4e, 0xa6, 0xcd}};

#define ATLAS_PROVIDER_NAME L"Atlas Login Agent"
#define ATLAS_CLSID_STRING L"{C3B1A0E6-6D1F-4B0E-9C57-2F1B7A9D4E58}"
