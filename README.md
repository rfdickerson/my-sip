# Janus C++ SIP Smoke Test

This is a minimal **C++ SIP smoke test** for joining a WebEx SIP URI using **PJSIP (pjsua2)** with CMake + Ninja. It logs call state and media state (audio/video).

## Prereqs
- Linux
- CMake + Ninja
- PJSIP built with pjsua2 and video support (H.264 + Opus)

## Option A: Build PJSIP yourself
Build and install PJSIP to a prefix, then set `PJSIP_ROOT`.

Example (from PJSIP repo root):
```bash
./configure --enable-shared --prefix=$HOME/pjsip-install
make -j
make install
```

Then build this project:
```bash
cmake -S janus_cpp -B janus_cpp/build -G Ninja -DPJSIP_ROOT=$HOME/pjsip-install
cmake --build janus_cpp/build
```

## Option B: Vendor PJSIP and let CMake build it
Place PJSIP in `janus_cpp/third_party/pjsip` and run:
```bash
cmake -S janus_cpp -B janus_cpp/build -G Ninja -DBUILD_PJSIP=ON
cmake --build janus_cpp/build
```

## Run
```bash
./janus_cpp/build/sip_smoke \
  --sip-uri "sip:26644214992@rfdickerson-3xbj.webex.com" \
  --local-id "sip:smoketest@localhost" \
  --display-name "SmokeTest" \
  --transport udp \
  --max-seconds 300
```

Run with null devices (recommended on servers):
```bash
./janus_cpp/build/sip_smoke \
  --sip-uri "sip:26644214992@rfdickerson-3xbj.webex.com" \
  --local-id "sip:smoketest@localhost" \
  --display-name "SmokeTest" \
  --transport udp \
  --max-seconds 300 \
  --no-null-audio
```

If WebEx requires TLS, try:
```bash
./janus_cpp/build/sip_smoke \
  --sip-uri "sips:26644214992@rfdickerson-3xbj.webex.com" \
  --local-id "sip:smoketest@localhost" \
  --display-name "SmokeTest" \
  --transport tls \
  --max-seconds 300
```

If you have a SIP device registration, register first:
```bash
./janus_cpp/build/sip_smoke \
  --meeting-id "26644214992" \
  --local-id "sip:DEVICE_ID@TENANT_DOMAIN" \
  --display-name "SmokeTest" \
  --transport tls \
  --registrar-uri "sips:YOUR_REGISTRAR:5061;transport=tls" \
  --registrar-ip "YOUR_REGISTRAR_IP" \
  --auth-realm "bcld.webex.com" \
  --auth-user "SIP_USERNAME" \
  --auth-pass "SIP_PASSWORD" \
  --contact-forced "sip:DEVICE_ID@YOUR_IP:PORT;transport=tls" \
  --force-sips-contact \
  --disable-secure-dlg-check \
  --wait-for-register \
  --register-optional \
  --register \
  --no-prefer-opus \
  --stats-interval 5 \
  --sip-keepalive 30 \
  --record-file ./webex_audio.wav \
  --max-seconds 300
```

Or use a config file:
```bash
./janus_cpp/build/sip_smoke --config janus_cpp/sip_smoke.conf
```

## Notes
- This is a signaling + basic media smoke test.
- If WebEx requires SRTP, ensure your PJSIP build has libsrtp.
- If H.264/Opus fail to negotiate, we may need codec priority tweaks.
