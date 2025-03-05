#pragma once

#using "DeviceId.dll";

using namespace DeviceId;
using namespace System;

public ref class AesEncryptDeviceIdComponentEncoder : public IDeviceIdComponentEncoder
{
private:
	char* signatureKey_;

public:
	AesEncryptDeviceIdComponentEncoder(char* signatureKey) {
		signatureKey_ = signatureKey;
	};

	virtual String Encode(IDeviceIdComponent^ component);

};

