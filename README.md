This repository contains the code for our attack presented in the paper ["Help, my Signal has bad Device! Breaking the Signal Messenger’s Post-CompromiseSecurity through a Malicious Device](https://eprint.iacr.org/2021/626), to appear at DIMVA 2021.

`Program.cs` implements the dummy device for simulating the Signal phone app.

The implementation depends on [ZXing.Net](https://github.com/micjahn/ZXing.Net) (for scanning QR codes) and [libsignal-service-dotnet](https://github.com/signal-csharp/libsignal-service-dotnet) (for Signal API requests). The latter has been slightly fixed to make the device registration work (see [patches](patches/) folder).
