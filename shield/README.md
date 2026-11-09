# Muse Gadget — Shield port

Status 2026-11-08 (Leg B2): **pairing v5 setup protocol + steady-state
link session PORTED (v0.4.0) and verified; app installed on the Shield,
SDK token provisioned into app-private storage, service stopped,
ready to pair.** Pairing itself is Jonathan's step (see "Ready-to-pair"
below) — it has NOT been run yet. Mic capture remains VERIFIED
UNAVAILABLE to apps on this Shield as equipped (see the voice probe
verdict below); voice notes are wired in code, awaiting an audio input.

**v0.4.1 rename (2026-11-08, Jonathan's order — "fix the hyphen and
name everywhere"):** the BLE pairing name now follows the ESP32 /
Home Link convention **with hyphen — `MuseGadget-FA76F8`** (was
`MuseGadgetFA76F8`, the Linux-port style; `Identity.bleName()` is the
single source, so the adapter name, scan-response name, and logs all
carry it), and the link registers under the friendly display name
**"Shield TV"** (`GadgetService.DISPLAY_NAME`, sent as
`link.register`'s `display_name` — previously the BLE name; mirrors
the Windows port's separate `DISPLAY_NAME = "PC"`). Node id unchanged
(`homelink-fa76f8`). versionCode 5 / versionName 0.4.1, APK 78,251 B,
SHA-256 `c2c20ecb9c02bfb7ef5570ddc9ce8455d493f06b18e6492ae12d00358836804c`.
Verified: desktop SELFTEST vectors PASS, identity check prints
`MuseGadget-FA76F8`, on-device logcat shows `advertise
onStartSuccess name=MuseGadget-FA76F8 paired=false`
(`evidence/v0.4.1-ondevice-logcat.txt`).

**v0.4.2 correction (2026-11-08, Jonathan's ruling — the SDK-canonical
no-hyphen form is the fleet standard):** this **reverts the v0.4.1
BLE-name change above**. `Identity.BLE_NAME_PREFIX` is back to
`"MuseGadget"`, so `bleName()` returns **`MuseGadgetFA76F8`** — the
canonical form the SDK specifies (linux `identity.py` / `AGENTS.md`:
the apps compare the text after the prefix with the suffix after
`homelink-` in the node id). The ESP32 Home Link — the fleet's only
hyphenated name (`MuseGadget-DDA658`) — will be renamed to the
no-hyphen form to match, instead of the ports converging on the
hyphen. The v0.4.1 **display name "Shield TV" is retained**
(`GadgetService.DISPLAY_NAME`, unchanged). Node id unchanged
(`homelink-fa76f8`). versionCode 6 / versionName 0.4.2, APK 78,251 B,
SHA-256 `e13982c5e0a13b1b3b6b3c7e624a89a0b2a09991e278d0fcc3521fb6c6e4a355`.
Verified: desktop SELFTEST vectors PASS and identity check prints
`MuseGadgetFA76F8`; installed over v0.4.1 (`install -r`, app data
preserved); on-device SELFTEST PASS (all); logcat shows `advertise
onStartSuccess name=MuseGadgetFA76F8 paired=false` with the adapter
renamed to `MuseGadgetFA76F8`
(`evidence/v0.4.2-ondevice-logcat.txt`). Pair window reopened on
install; pairing itself is still Jonathan's step (below).

**v0.4.3 final naming (2026-11-08, Jonathan's FINAL ruling —
hyphenated, matching the ESP32 firmware as shipped):** this
**supersedes the v0.4.2 correction above**. The deciding fact:
Meta's ESP32 firmware constructs its BLE name **with** a hyphen in
its own identity code (`esp32/main/identity.c`,
`muse_video_wifi.c` — `MuseGadget-%02X%02X%02X` from the MAC), so
the hyphenated form is the reference as shipped and the Linux
client's no-hyphen form is the outlier. Fleet standard, final:
**hyphenated everywhere.** `Identity.BLE_NAME_PREFIX` is
`"MuseGadget-"` again, so `bleName()` returns
**`MuseGadget-FA76F8`** (the v0.4.1 name, now on final footing);
the no-hyphen v0.4.2 window was stopped before install. The
**display name "Shield TV" is retained**
(`GadgetService.DISPLAY_NAME`, unchanged). Node id unchanged
(`homelink-fa76f8`). versionCode 7 / versionName 0.4.3
(`LinkSession.CLIENT_VERSION` also corrected to 0.4.3 — it had
lagged at 0.4.1), APK 78,251 B, SHA-256
`f758d0a609aaeff4c767fb19dc1e0506064a7da71076c68779da0cbda0671530`.
Verified: desktop SELFTEST vectors PASS and identity check prints
`nodeId=homelink-fa76f8 bleName=MuseGadget-FA76F8`; installed over
v0.4.2 (`install -r`, app data preserved, device still unpaired);
logcat shows `advertise onStartSuccess name=MuseGadget-FA76F8
paired=false` with the adapter renamed to `MuseGadget-FA76F8`
(`evidence/v0.4.3-ondevice-logcat.txt`). Pair window reopened on
install; pairing itself is still Jonathan's step (below).

**v0.4.4 diagnostic build (2026-11-08, after the first real-app
pairing attempt):** the 22:34 EST pairing ran the full BLE v5 flow
(encrypted session, `wifi_scan` answered, `provision_v2` received,
`wifi_connecting`/`wifi_connected` sent) and then failed at the
provision verify step — `GadgetService.doProvision` →
`MuseApi.fetchVms` returned an **empty VM list** (HTTP 200 path),
so provisioning was refused with "the account has no VM yet" and
the app showed "Couldn't connect". The Java verify mirrors the
SDK's `pair.py` `_verify_and_save`, so the empty list is real API
data for the app-issued credentials; what was missing is *which*
API root answered. v0.4.4 changes **no pairing behavior** — it only
adds host-only diagnostic logging at the verify step:
`GadgetService` logs the hosts of the app-supplied `api_url` /
`api_url_v2` and which root `fetchVms` will use; `MuseApi.fetchVms`
logs the root host, the HTTP status (and the exception path when no
status was read), and the parsed VM count. Tokens, full URLs and
response bodies are never logged (a `fetch_vms` body carries VM
auth tokens). Data first — no fix attempted in this build.
versionCode 8 / versionName 0.4.4, APK 78,251 B, SHA-256
`d5d7c4306dfb0260b00859d9487bf0274862047e809c19e63cade1fd26fcc464`.
Verified: desktop SELFTEST vectors PASS and identity check prints
`nodeId=homelink-fa76f8 bleName=MuseGadget-FA76F8`; installed over
v0.4.3 (`install -r`, app data preserved, device still unpaired);
logcat shows `service onCreate (v0.4.4)` and `advertise
onStartSuccess name=MuseGadget-FA76F8 paired=false`
(`evidence/v0.4.4-ondevice-logcat.txt`). Pair window reopened on
install; the re-pairing attempt is Jonathan's step (below), and the
new log lines land under the same `MuseGadgetShield` tag.

**v0.4.5 fix (2026-11-08, root cause of the pairing refusal —
`fetch_vms` response-schema drift):** the v0.4.4 diagnostic retry
(22:41 EST) logged it plainly: `api_url`/`api_url_v2` hosts both
`api.muse.ai`, `fetch_vms: HTTP 200, vms=0` — a healthy response
parsing as zero VMs. The bug was ours: `MuseApi.fetchVms` read the
VM list from the key **`"vms"`** with entry fields
`"auth_token"` / `"is_default"`, but the real Muse API returns
**`"vm_list"`** with entries keyed **`"vm_id"` /
`"vm_auth_token"` / `"default"`** (confirmed against both
references: linux SDK `muse_api.py` `data.get("vm_list")` and the
ESP32 `vm_api.c`). The desktop fake VM had been built to our own
wrong schema, which is why every loopback test passed while the
real app could never pair. The fix: parsing factored into
`MuseApi.parseFetchVms` reading `vm_list` (entries missing
`vm_id`/`vm_auth_token` skipped); a top-level `"error_title"` /
`"backend_error_code"` on an HTTP 200 is now treated as failure
(throws, logging only the error CODE value, never the body). The
v0.4.4 diagnostic logging (host, HTTP status, VM count) is kept.
Also aligned: `refreshDeviceToken` now unwraps a top-level
`"payload"` object before reading the token pair, matching SDK
`muse_api._post_refresh`. **Regression fixture:**
`tests/FetchVmsParseMain.java` parses a synthetic response in the
REAL schema (asserts 1 VM with the right id/token/default, plus
incomplete-entry skipping and the error-payload throw) and is
wired into `build.sh` as step [6/6] alongside the SELFTEST
vectors, so every build runs it. BLE name and display name
unchanged (`MuseGadget-FA76F8` / "Shield TV"). versionCode 9 /
versionName 0.4.5, APK 78,251 B, SHA-256
`e694165e6d0032cd0502a0ce842037e00d4ad7e519faec8e7b617f14057fa35f`.
Verified: build.sh desktop checks PASS (SELFTEST vectors +
`FETCHVMS PARSE PASS (all)`); installed over v0.4.4 (`install -r`,
app data preserved, device still unpaired); on-device logcat shows
`service onCreate (v0.4.5)`, identity
`node=homelink-fa76f8 bleName=MuseGadget-FA76F8`, and `advertise
onStartSuccess name=MuseGadget-FA76F8 paired=false`
(`evidence/v0.4.5-ondevice-logcat.txt`). Pair window reopened on
install; the re-pairing attempt is Jonathan's step (below).

**v0.4.6 audio capture probe (2026-11-08, on-demand — no pairing
behavior changes):** pairing completed live after the v0.4.5 fix
(`pairing.json` persisted, link registered as `homelink-fa76f8`), so
this build adds the measurement tool the voice question needs next.
New service action
`com.jonathancruzate.musegadgetshield.action.PROBE_AUDIO` runs
`AudioProbe` on a worker thread inside the running service (the
BLE/link session is untouched). It closes the three gaps of the
v0.3 probe — that one only checked `getState()` at construction,
unrouted, never recording, and never while the Shield remote's mic
button was held (the remote streams only while held): for every
enumerated input device it builds an `AudioRecord` (Builder,
PCM16 mono, buffer = max(minBuf×4, 8192)), routes it to that exact
device (`setPreferredDevice` on the instance — the API 30 Builder
has no routing method), starts recording for real, discards ~700 ms,
then measures peak / RMS over ~700 ms, for sources
VOICE_COMMUNICATION and MIC at 48 kHz. All lines log under
`MuseGadgetShield` with the `AUDPROBE` prefix; sweep capped at
~60 s (the idle run took ~10 s). **Idle baseline**
(`evidence/v0.4.6-audprobe-idle.txt`): with per-device routing, the
type 21 (BUS, id 15) and type 15 (BUILTIN_MIC, id 5) inputs now
**initialize and record** — unlike v0.3's all-STATE_UNINITIALIZED —
but deliver pure digital silence at idle (peak=0, rms=0.0 over
~45k / ~35k samples per combo). Type 25 (REMOTE_SUBMIX, id 7)
initializes but `startRecording` never reaches RECORDING
(`outcome=startFailed`) for both sources. So the input stubs open
when routed explicitly yet carry no signal while nothing streams —
the decisive run is the same probe fired while the remote's mic
button is held. versionCode 10 / versionName 0.4.6, APK 82,347 B,
SHA-256 `840fb86fefcb59c3b15376941804271a26df25fe1bb1fa82775f0bfd6ee01d9c`.
Installed over v0.4.5 (`install -r`, data preserved —
`pairing.json` intact); on relaunch the log shows `paired already;
link loop running` and `Link session registered as
homelink-fa76f8` (22:51 EST), then the idle probe above.

**v0.4.7 hold probe (2026-11-08, on-demand — no pairing behavior
changes):** tonight's PROBE_AUDIO live runs produced three results.
(1) **Idle:** the routed BUS (type 21) and builtin (type 15)
recorders initialize and record pure digital silence (peak=0).
(2) **Wrong button held:** the same sweep fired while a non-mic
remote button was held — silence everywhere, as expected.
(3) **Correct mic button held** (remote streaming to Assistant):
every `AudioRecord` construction in the sweep threw
`UnsupportedOperationException` ("Cannot create AudioRecord") —
during streaming the input is **exclusively claimed**, so no new
recorder can even be built. One configuration therefore remained
untested: recorders created *and started* while idle, kept open,
and measured *while the button press begins* — does a pre-opened
recorder get fed, get silenced, or get killed when streaming
starts? v0.4.7 adds exactly that test as a new service action,
`com.jonathancruzate.musegadgetshield.action.PROBE_HOLD`
(`AudioProbe.runHold`): it opens two recorders up front — (a) BUS
device (type 21) + VOICE_COMMUNICATION, (b) builtin device
(type 15) + MIC, both 48 kHz routed via `setPreferredDevice`
(same construction as v0.4.6; open outcomes logged as `AUDHOLD
open device=<id> source=<s> state=<n>`) — starts both, then for
15 s reads each continuously on its own thread, logging peak /
RMS per 1-second window (`AUDHOLD t=<sec> device=<id> peak=<p>
rms=<r> readErr=<e>`); new read-error codes and recording-state
changes are logged immediately with their code; either recorder
failing to open is logged and the other continues. After 15 s
both are stopped + released (`AUDHOLD DONE`). Like PROBE_AUDIO
(kept intact), it creates/releases only its own AudioRecords —
no BLE/link/pairing state is touched. **The hold probe was NOT
fired at install time**; the main agent triggers it live with
Jonathan holding the button. versionCode 11 / versionName
0.4.7, APK 86,443 B, SHA-256
`c5e3279af8df599ffed83cb0ea4df1cdb7fb1af0957bf852e403a26372cca649`.
Verified: build.sh desktop checks PASS (SELFTEST vectors +
`FETCHVMS PARSE PASS (all)`); installed over v0.4.6 (`install
-r`, data preserved — `pairing.json`, `identity.json`,
`sdk_token` all intact); on relaunch the log shows `service
onCreate (v0.4.7)`, `paired already; link loop running, pair
window stays closed`, and `Link session registered as
homelink-fa76f8` (23:03 EST), service foreground
(`evidence/v0.4.7-ondevice-logcat.txt`). **PROBE_HOLD is armed
and ready for the live run.**

**v0.5.0 voice relay to phone (2026-11-08, Jonathan's directive
23:08 + design change 23:10):** the Shield's mic paths are verified
unusable by apps (probe matrix complete: idle = silence, streaming =
exclusively claimed / policy-muted), so this build adds an optional
mode in which the Shield stops being a microphone endpoint and voice
mode activates on Jonathan's phone instead. MainActivity is now a
couch UI (large, D-pad-focusable controls) with a persisted
**"Voice relay to phone"** toggle (`SharedPreferences` file
`voice_relay`, key `relay_to_phone`, default OFF) and a status line.
**There is no Talk button** (design change): the toggle flip itself
is the relay signal.

Behavior matrix:

| Toggle | Behavior |
|---|---|
| OFF (default) | Normal gadget. RECORD_AUDIO permission intact; probe actions run as before. Switching OFF sends nothing. |
| OFF→ON flip in the UI | Persists ON; strips the app's own RECORD_AUDIO access (see strip semantics); gates off every capture path (both probe actions log `AUDPROBE skipped: voice relay on` / `AUDHOLD skipped: voice relay on` and do nothing — enforced both at GadgetService dispatch and inside AudioProbe); sends the relay activation message **exactly once for that enable** via GadgetService action `…action.RELAY_ON` → `LinkService.sendChat` → `LinkSession.sendChat` (text payload to `/chat/stream`, the same session path `sendVoice` posts WAV turns to). Outcome logged as `RELAY` lines, host + status only (`RELAY activation sent host=hatch.metaaivm.com path=/chat/stream replies=N` / `RELAY activation failed host=… error=HTTP nnn`). |
| Restart with toggle already ON | Restores ON, re-attempts the strip (idempotent), capture stays gated — and does **not** resend the message. Sends happen only on a UI OFF→ON transition. |

**Strip semantics:** the runtime self-revoke
(`Context.revokeSelfPermissionOnKill`) is API 31+; the Shield is
API 30, so `VoiceRelay.stripMicPermission` attempts it reflectively
(it takes effect on newer devices) and on API 30 the enforcement is
the code gate above — the log states this plainly
(`RELAY mic strip: revokeSelfPermissionOnKill unavailable on API 30;
capture paths are gated by the relay flag instead`), and
`RECORD_AUDIO` remains `granted=true` at OS level here. Turning the
toggle OFF never auto-re-grants the permission; on a device where
the revoke landed, re-grant via Settings > Apps > Muse Gadget
Shield > Permissions if the mic is ever wanted again.

**The relay message** (verbatim, with the send-time timestamp
appended by `VoiceRelay.buildMessage`):

> [Voice relay — Shield TV] Jonathan activated voice from the Shield TV in the living room. The TV has no usable microphone (verified), so voice mode should run on his phone. Context: he is at the TV and wants to talk to Muse and control the Shield TV. Please bring up voice on the phone for this conversation. (Activated `<yyyy-MM-dd HH:mm:ss zzz, device-local>`.)

**TV home-row presence:** `MainActivity`'s launcher filter carries
`LEANBACK_LAUNCHER` (present since the prototype) and the manifest
now adds a TV banner (`android:banner="@drawable/tv_banner"` on the
application and the activity; `res/drawable/tv_banner.png`, 320×180,
dark background, "Muse Gadget / SHIELD TV"); `android.software.leanback`
stays `required=false`, so the app shows in the Shield's apps row
for couch access.

versionCode 12 / versionName 0.5.0, APK 94,707 B, SHA-256
`9548184d7159f4f4cda17047cb6db351770d8271c98852fe0105aa22dae70394`.
Verified: build.sh desktop checks PASS (SELFTEST vectors +
`FETCHVMS PARSE PASS (all)`); installed over v0.4.7 (`install -r`,
data preserved — `identity.json`, `pairing.json`, `sdk_token`
intact); `dumpsys package` shows versionName 0.5.0 / versionCode 12;
on relaunch `Link session registered as homelink-fa76f8`
(23:12 EST), GadgetService foreground. **Live observation during
verification:** ~9 s after MainActivity appeared on the TV, the
toggle was flipped ON through the UI (the builder sent no input
events beyond a wake keyevent; the flip arrived via the real
listener path — consistent with a couch test by Jonathan, who had
just ordered the design): the log shows `RELAY voice relay ON`, the
strip attempt, `RELAY activation action received`, and
`RELAY activation sent host=hatch.metaaivm.com path=/chat/stream
replies=1` — i.e. one relay message was delivered to the chat
stream, and the toggle remains ON (persisted `relay_to_phone=true`).
UI screenshot: `evidence/v0.5.0-mainactivity.png` (toggle ON,
status line reading "Voice relay ON — microphone stripped on this
TV; voice activation sent to your phone."). A fresh install renders
the toggle OFF by default.

**v0.5.1 speech-recognition probe (2026-11-08, on-demand — no other
behavior change):** the AudioRecord matrix is closed — direct
capture from this app can never hear the remote (idle pipes carry
silence; while the remote streams, the input is exclusively claimed
or policy-muted for direct capture). But that verdict covers only
one capture path. The voice search inside apps like YouTube never
opens an AudioRecord: the app calls the Android
**`SpeechRecognizer`** API and the *system* recognition service —
part of Google's privileged stack — does the listening and returns
text. No audio ever enters the calling app's process, so the
AudioRecord lockout does not apply to it. Tonight's context for
testing exactly that: the r/ShieldAndroidTV workaround for the
remote's mic button (Button Manager remaps it to **keycode 84,
`KEYCODE_SEARCH`**) works by making the button trigger apps'
*native* voice search instead of Google Assistant — and that
in-app voice search rides this same system recognition service.
If the service path is open to this app, the remote button can be
wired straight to it; if it is closed to third-party apps, the
phone relay stays the only voice route.

v0.5.1 therefore adds exactly one thing: service action
`…action.PROBE_SPEECH` → `SpeechProbe`, one 25 s listening session
per firing. It logs `SPEECH available=<isRecognitionAvailable>`
first, creates the `SpeechRecognizer` on the main Looper (the API
requires the main thread; the session is held statically so it
cannot be GC'd mid-flight), and a `RecognitionListener` logs every
callback under the `SPEECH` prefix: `readyForSpeech`,
`beginningOfSpeech`, `endOfSpeech`, the running max RMS (logged
whenever the max climbs by ≥3 dB and again in the DONE line),
buffer-received counts, partial transcripts as they arrive, and on
results the top transcript + confidence. `onError` logs the numeric
code AND its symbolic name (e.g. `ERROR_NO_MATCH`). The intent is
`ACTION_RECOGNIZE_SPEECH` with `LANGUAGE_MODEL_FREE_FORM`,
`EXTRA_PARTIAL_RESULTS`, `EXTRA_MAX_RESULTS=3`, and
`EXTRA_CALLING_PACKAGE`. A hard stop destroys the recognizer after
25 s if no terminal callback lands; exactly one
`SPEECH DONE outcome=<results|error|timeout> maxRms=<v>` line ends
every run. The relay gate applies like every capture path: while
voice relay is ON, the probe logs `SPEECH skipped: voice relay on`
and does nothing (enforced at GadgetService dispatch and inside
`SpeechProbe`). No pairing, BLE, link, or relay behavior changed.

versionCode 13 / versionName 0.5.1, APK 98,803 B, SHA-256
`50072ed7b9282a3001656dd369d60a1e0ade0752ffd98a271d792e3d691af267`.
Verified: build.sh desktop checks PASS (SELFTEST vectors +
`FETCHVMS PARSE PASS (all)`); installed over v0.5.0 (`install -r`,
data preserved — `identity.json`, `pairing.json`, `sdk_token`
intact, `relay_to_phone=true` still persisted); `dumpsys package`
shows versionName 0.5.1 / versionCode 13; on relaunch `Link session
registered as homelink-fa76f8` (23:18 EST), GadgetService foreground
(`evidence/v0.5.1-ondevice-logcat.txt`). **PROBE_SPEECH is armed
and NOT fired** — at verification time the relay toggle is ON, so
firing it now would (correctly) only log the skip line; the live
test runs with the main agent and Jonathan with relay OFF.

**v0.6.0 voice mode (2026-11-08, Jonathan's directive 23:16 —
"built in search triggers by keycode that activates muse gadget
sdk voice mode with full avatar", plus his two 23:45 refinements:
Google Assistant MUST NOT pop up, and the voice UI carries
official Muse branding):** the probe's proof became the product.
Round 3 of the speech probe (23:43 EST) returned a final
transcript at 0.97 confidence — the public Katniss recognition
service is open to this app even though direct AudioRecord
capture is closed. v0.6.0 builds voice mode on exactly that lane.

*Voice UI (`VoiceActivity`, full-screen, TV-first).* Brand header:
the **authentic Muse logo** — extracted from the installed Muse
app itself (com.facebook.aura 15.0.0.3.156: its adaptive launcher
icon's foreground vector, gradient stops and path data
machine-extracted via aapt2, never hand-drawn; see
`res/drawable/muse_logo.xml`) on a white rounded chip next to the
"Muse" wordmark. Below it, **Stef's avatar large and centered**
(the active avatar, `avatar-1792645695164555342-10.webp`,
downscaled to a 512×512 PNG at
`res/drawable-nodpi/stef_avatar.png`), a state line
(Listening… / Thinking… / Speaking… / idle "Hold the remote mic
button and talk to me"), captions for the last heard transcript
and the last reply, and a subtle scale-pulse on the avatar while
listening. Back exits; DPAD-friendly throughout. MainActivity
gained the same brand header and a prominent focusable "Voice
mode" button.

*Trigger + Assistant suppression (`KeyTriggerService`).* An
AccessibilityService declared with `canRequestFilterKeyEvents`
(`res/xml/key_trigger_service.xml`; it retrieves no window
content). `onKeyEvent` logs **every** key as
`KEYPROBE code=<n> action=<down|up> repeat=<r>` and
**consumes** `KEYCODE_ASSIST` (219), `KEYCODE_VOICE_ASSIST`
(231), and `KEYCODE_SEARCH` (84) on down AND up (returns true),
so the press never routes to the system's
VoiceInteractionService — Google Assistant does not pop up. The
first (repeat-0) down launches VoiceActivity. `VoiceActivity`
consumes the same keys in its own `onKeyDown` while foreground,
so repeat presses inside voice mode can't summon Assistant
either. GadgetService also accepts
`…action.VOICE_MODE` (startservice) as the remote/test launch
lane.

**KEYPROBE verification plan (the honest split).** Verified at
build time: the settings route enables the service and it
**binds** — after appending our component to
`enabled_accessibility_services` (Projectivy Launcher's existing
service preserved) and setting `accessibility_enabled=1`,
logcat shows `KEYPROBE trigger service connected (key filtering
requested)` and `dumpsys accessibility` lists it under Enabled
services. That is partial evidence only. Whether this Shield
build actually delivers the remote's mic key to `onKeyEvent` is
proven by the **live press test**, still owed: Jonathan presses
the remote mic button once while watching logcat — success is
`KEYPROBE code=219` (or 231/84) logged, VoiceActivity opening,
and no Assistant UI. Until that runs, Assistant suppression is
designed-and-bound, not live-proven. KEYPROBE stays in the build
as the standing verification aid.

*Voice loop.* On open (relay OFF) the activity starts one
activity-lifetime `/chat/subscribe` stream (re-opened on the
current link session whenever it ends) and auto-starts listening
after ~1.2 s so the subscription is live before the first reply
can arrive. Recognition sessions reuse SpeechProbe's exact
parameters and one-shot lifecycle (FREE_FORM, partials,
maxResults 3, calling package; created per session, destroyed at
the terminal callback; 25 s watchdog). On a final transcript:
caption it, then a worker runs the chat turn — `sendChat(text,
null, "voice")` (new `output_modality` parameter on the send)
whose response is only an acknowledgement, and the new
**`ReplyTracker`** (a faithful port of the SDK's
`muse_turn.py`/`service.py send_and_wait`) follows the reply
TEXT through the subscription: pre-ack events are held, events
bind to the turn by ack message id / parent chain, delta events
accumulate into text, and completion is decided by
agent/task status plus the SDK's quiet windows (1 s after
message_done with replies, 3 s otherwise). **Reply-text capture
therefore ships working** — the v0.5.x gap (stream handling that
counted replies but discarded their text) is closed. The reply
is captioned and spoken, then the loop re-listens. Two
consecutive failed/empty sessions (or a failed turn) drop the
loop to the idle prompt; a mic-button press re-arms it. The
silent-room behavior is already verified (below): two
`ERROR_NO_MATCH` sessions, one retry, then idle — exactly as
designed.

*Mouth — which TTS shipped.* Primary: the SDK's own TTS path —
`streamTts(replyMessageId)` returns the reply's synthesized MP3,
played through MediaPlayer (the real Muse voice). Fallback:
Android `TextToSpeech` (Locale.US) when the stream path fails or
no message id is available. Captions-only if both fail. The
`VOICE mouth=<streamTts|androidTts|none>` log line records which
mouth each reply used. Neither mouth has spoken a reply yet —
the first real voice turn is the live test — so the mouth order
is shipped-and-logged, pending that proof. (On the verification
open the Android fallback did initialize:
`VOICE androidTts ready=true`.)

*Relay precedence.* While the voice-relay toggle is ON,
VoiceActivity shows "Voice is relayed to your phone" and never
listens, and the trigger still opens the activity (which then
just shows the relay state). All v0.4.5 fixes, the pairing/link,
the relay toggle + gate, and every probe action are unchanged.

versionCode 14 / versionName 0.6.0, APK SHA-256
`9ac21df6866825dda69045a57b91d2a8b1d5eb40c57b16da9bca68280d4a5666`.
Verified: build.sh desktop checks PASS (SELFTEST vectors +
`FETCHVMS PARSE PASS (all)` + full desktop compile — which now
includes all v0.6.0 sources); installed over v0.5.1
(`install -r`, data preserved — `identity.json`, `pairing.json`,
`sdk_token` intact); `dumpsys package` shows versionName 0.6.0 /
versionCode 14; on relaunch `Link session registered as
homelink-fa76f8`, GadgetService foreground; accessibility
service enabled and bound via the settings lane (above);
VoiceActivity launched via the `…action.VOICE_MODE` service
action and screencapped (`evidence/v0.6.0-voiceactivity.png`).
Skill: `docs/SKILL.md` in this project and the installed copy at
`~/workspace/custom-skills/local-muse-gadget-shield/SKILL.md`.

## Hardware gate verdict (the question this leg had to resolve)

This Shield (SHIELD Android TV, `mdarcy`, NVIDIA, Android 11 / SDK 30)
**supports BLE peripheral mode**. Real evidence, not inference — prototype
logcat (`MuseGadgetShield` tag, files in `evidence/`):

- `pm has-feature android.hardware.bluetooth_le` → `true`;
  `pm list features` also shows bluetooth, leanback, television.
- `BluetoothAdapter.getBluetoothLeAdvertiser()` → non-null;
  `isMultipleAdvertisementSupported=true`.
  `isLeExtendedAdvertisingSupported=false` (also coded-PHY / 2M /
  periodic all false) → **legacy 31-byte advertising only**.
- Advertiser `onStartSuccess` twice per run: Phase A (service UUID +
  manufacturer data, no name) and Phase B (name `MuseGadget-FA76F8` in
  the **scan response**, adapter renamed) — `mode=2 connectable=true`.
- GATT server: `addService returned=true`,
  `onServiceAdded status=0 uuid=7fdd3d1c-38ea-46cf-8b46-314ecf5f240c`,
  and connection-state callbacks fired. `dumpsys bluetooth_manager`
  during a run shows this app registered as a GATT server
  (`app_if: 5, com.jonathancruzate.musegadgetshield`).
- Corroboration: the Shield already runs a system GATT server for its
  remote (`com.nvidia.shield.remote.server`).

### Findings that shape the real port

1. **31-byte legacy limit is the binding constraint.** v0.1 put the name
   in the advertising packet with the UUID + manufacturer data →
   `onStartFailure errorCode=1` (DATA_TOO_LARGE). v0.2+ splits exactly
   like the payload budget requires: advertising packet = setup service
   UUID + manufacturer paired-flag (`0xFFFF` → `[0]`); scan response =
   device name. That succeeds.
2. **`BluetoothAdapter.setName()` works but is asynchronous** — v0.1
   read the old name back immediately after a `true` return; dumpsys
   showed the new name moments later. The service now polls for the
   rename, and restores `SHIELD` on stop (verified by dumpsys after
   every test run: name back to `SHIELD`, service gone).
3. **Self-scan does not see the Shield's own advertisement** on this
   stack (12 s service-UUID-filtered scan, 0 results while advertising).
   External visibility rests on the advertiser success callbacks + GATT
   registration until the phone-side scan at pairing time.
4. Identity: node id `homelink-fa76f8`, BLE name
   `MuseGadget-FA76F8` (hyphenated — the ESP32 firmware form as
   shipped; the fleet's final standard per the owner's ruling,
   after the v0.4.1 → v0.4.2 → v0.4.3 sequence at the top) —
   suffixes match, persisted in the app's private prefs across
   reinstalls.

## Voice probe verdict (scope update, 2026-11-08 20:44)

**An Android TV app cannot record voice on this Shield today.**

- `AudioManager.getDevices(GET_DEVICES_INPUTS)` → 3 inputs: type 21
  (BUS, 48 kHz), type 25 (REMOTE_SUBMIX, 16/48 kHz), type 15
  (BUILTIN_MIC, 8–48 kHz incl. 24 kHz). No Bluetooth-SCO/remote-mic
  input, no USB input.
- With `RECORD_AUDIO` verified granted in-app, **all 12 AudioRecord
  combinations failed**: sources MIC / DEFAULT / VOICE_RECOGNITION /
  CAMCORDER × 48 / 16 / 24 kHz → every one `state=0`
  (STATE_UNINITIALIZED), `PROBE mic RESULT captured=false`.
  The BUILTIN_MIC policy entry is a stub; there is no capture hardware
  behind it.
- **The Shield remote's microphone is not an app audio source.** It
  feeds Google Assistant through NVIDIA's private remote service; it
  never appears as an input device. Remote-mic capture is not a path.
- Working mic options, in order: **(1) a USB microphone / USB headset**
  plugged into the Shield — it would appear as a USB input device and
  AudioRecord should initialize (re-run this app's probe to confirm in
  one shot); **(2) phone-mic relay** — the phone records and forwards
  WAV to this app / the VM session (extra moving parts, attribution is
  by session so it can work, but it's a relay architecture, not a
  Shield mic); (3) remote mic — ruled out above.

## What the app does (v0.4.0, installed on the Shield, service stopped)

Package `com.jonathancruzate.musegadgetshield`, framework-only Java
(no AndroidX/Gradle; `build.sh` reuses the shield-wifi-sense toolchain).
APK 78,251 B, SHA-256 (v0.4.0)
`1105c21c9fe0d4994b734a3fd6b880c49da0c041d8a1a285369f687e0bf85231`.

Ported from the Linux reference (`~/workspace/muse-gadget-sdk/linux`),
class by class (`app/src/main/java/com/jonathancruzate/musegadgetshield/`):

- **Pairing v5** — `Pairing.java` (transcript, P-256 ECDH via JCA,
  HKDF-SHA256, AES-256-GCM records, generation/deadline rules),
  `SetupController.java` (`ble_setup.py`: RX chunk reassembly via
  `BleFraming.java`, command dispatch, encryption gating,
  `wifi_scan` → single open "current connection" entry,
  `provision_v2` → verify by fetching account VMs → persist
  `pairing.json` → `auth_ok`), `Hashes.java`, `Json.java`, `B64.java`,
  `X25519.java` (pure-Java RFC 7748 for Noise), `Identity.java`,
  `DeviceStore.java`.
- **Steady state** — `NoiseXx.java` (Noise XX initiator), `Proto.java`
  + `NoiseEnvelope.java` + `NoiseFraming.java` (protobuf service
  envelopes, 65,489 B transport chunking), `NoiseTransport.java`
  (stream-multiplexed service requests), `WsClient.java` (RFC 6455
  client), `MuseApi.java` (fetch_vms, device-token refresh),
  `LinkSession.java` (holds `POST /link-control`, `link.register` as
  `platform: "linux"` / `device_family: "homehub"`, `link.invoke` →
  `link.result`, unpair events, chat turns), `LinkService.java`
  (reconnect/backoff loop, 3 h token rotation, unpaired poll).
- **Executor** — deliberately minimal: one harmless read-only command,
  `device.info`; everything else returns an "unknown command"
  `link.result`. No shell on the TV.
- **Voice readiness (code only)** — `LinkSession.sendVoice` posts a
  WAV file item (≤ 2 MiB) to `/chat/stream` with
  `output_modality: "voice"`; `streamTts` fetches the spoken reply.
  No capture path exists yet (see the verdict above) — nothing records.
- `GadgetService` keeps the v0.3-proven BLE shape (Phase A/B
  advertising, adapter rename + restore) and hosts the setup
  controller; unpaired → 600 s pair window; paired → link loop only.
  Actions: default START, `.STOP`, `.FORCE_PAIR`, `.SELFTEST`,
  `.action.PROBE_AUDIO` (v0.4.6 on-demand audio capture probe),
  `.action.PROBE_HOLD` (v0.4.7 pre-opened-recorder hold probe),
  `.action.RELAY_ON` (v0.5.0 voice-relay activation send, fired by
  the MainActivity toggle's OFF→ON flip; both audio probe actions
  are gated off while the relay is ON), `.action.PROBE_SPEECH`
  (v0.5.1 system SpeechRecognizer probe — one 25 s listening
  session via the system recognition service; also relay-gated).

### Verification (2026-11-08, Leg B2)

- **SDK test vectors, production classes**: X25519 RFC 7748 §6.1 +
  the `community_app_v5` pairing vector — transcript hash, session id,
  client-finished decrypt, `pairing_confirmed` seal — PASS, on the
  desktop JVM AND on the Shield itself (`SELFTEST` action, logcat in
  `evidence/v0.4-ondevice-logcat.txt`: `SELFTEST PASS (all)`).
- **Cross-implementation pairing loopback**: the Java device
  (`SetupController` + `Pairing`) driven over stdio by a phone built
  from the SDK's own `build_transcript`/`derive_session_keys` and
  framing — full flow PASS: plaintext `wifi_scan` refused
  (`error_encryption_required`), `pairing_confirmed` opened with the
  SDK-derived key, `wifi_scan` offered the current-connection entry,
  `provision_v2` → `wifi_connecting → wifi_connected → auth_ok`,
  `pairing.json` persisted (`evidence/v0.4-desktop-tests.txt`).
- **Noise/link interop**: Java `LinkSession` against a fake VM built
  on the SDK's responder/envelopes — WS upgrade, Noise handshake,
  register (params asserted), invoke `device.info` + unknown-command
  error, chat text turn, voice turn (WAV item), TTS stream reassembled
  byte-exact, `link.unpaired` handled — PASS
  (`evidence/v0.4-link-interop.txt`). Desktop harness note: this
  sandbox blocks raw JVM sockets, so the test ran the WS leg through a
  Python pipe bridge (`tests/ws_bridge.py`); on the Shield the client
  connects directly.
- **On-device regression**: install over v0.3 (same signer),
  versionCode 4 / 0.4.0; identity migrated to FA76F8; GATT service
  registered; `advertise onStartSuccess` (both phases), adapter
  renamed; STOP restored adapter name to `SHIELD`, service gone,
  media session untouched (paused, same position).
- **Not exercised**: a real phone-driven BLE pairing (needs Jonathan's
  Muse app — his step below), a live session against the production
  VM (needs pairing first), and any microphone capture (impossible as
  equipped).

## Ready-to-pair (Jonathan's step, ~1 min)

The window must be open while pairing: ask Muse to start the gadget
service on the Shield first (it advertises for 600 s), then:

1. Muse app → **Settings > Devices > Developer mode → Add Device**.
2. Pick **`MuseGadget-FA76F8`** and accept the community warning.
3. Pick the offered network ("Use current connection").

On success the app sends `provision_v2`; the Shield verifies the
credentials against the account's VMs, persists `pairing.json`, the
`pairing_confirmed` record carries the SDK token (already provisioned
in app-private storage by the Leg B2 setup step — value never printed),
BLE tears down, and the link loop registers `homelink-fa76f8` with the
VM automatically.

## Remaining path

1. **Voice capture**: plug in a USB microphone / headset — expect a
   USB input device; re-run the v0.3 probe (`AudioRecord` init check),
   then record PCM, downsample to 24 kHz mono like
   `voice_audio.Pcm48To24`, wrap as WAV, and feed
   `LinkSession.sendVoice` (already wired). Spoken replies play via
   `streamTts` MP3 → MediaPlayer on the TV speakers.
2. **Realtime voice**: port `voice_call.py` (583 lines) + `voice_gate.py`
   ReplyGate. Requirements from the Linux reference + linux/AGENTS.md:
   paired store + exact `--vm-id`; a voice-only `LinkSession`
   (`register_device=False`); **app_id** (default `hatch-web`) set on
   the Noise upgrade query; admission `POST /voice/realtime` (end:
   `/voice/end-call`); admit only `mcu-wearable` calls; wait for call/
   session readiness before uploading; PCM16LE mono 24 kHz in
   960-sample (40 ms) frames; half-duplex by default (TV speakers +
   room mic make full duplex an echo trap — the CLI itself recommends
   headphones for full duplex); send the `hatch.voice.capability.offer`
   `end_call_stop` record; bounded idle (45 s) / overall (300 s)
   timeouts. Plus step 4's mic fix for live input and 24 kHz
   AudioTrack playback for output. **If realtime lands, the Muse
   phone app on the Shield is unnecessary for voice — the gadget
   session carries it natively.**

## Evidence

`evidence/`: v0.5.1 — `v0.5.1-ondevice-logcat.txt` (install/start
run of the SpeechRecognizer probe build; probe armed, not fired).
v0.5.0 — `v0.5.0-ondevice-logcat.txt` (install/start
run + the live toggle flip and relay send), `v0.5.0-mainactivity.png`
(couch UI, toggle ON). v0.4.7 — `v0.4.7-ondevice-logcat.txt` (install/start
run of the PROBE_HOLD build; hold probe armed, not fired).
v0.4.6 — `v0.4.6-audprobe-idle.txt` (idle AUDPROBE
sweep of the capture probe build). v0.4.5 — `v0.4.5-ondevice-logcat.txt` (install/start
run of the fetch_vms vm_list fix build). v0.4.4 — `v0.4.4-ondevice-logcat.txt` (install/start
run of the provision-verify diagnostic build). v0.4.3 — `v0.4.3-ondevice-logcat.txt` (install/start
run of the final hyphenated build). v0.4.2 — `v0.4.2-ondevice-logcat.txt` (install/start/
SELFTEST run of the no-hyphen correction build). v0.4 — `v0.4-desktop-tests.txt` (SDK vectors + pairing
loopback), `v0.4-link-interop.txt` (Noise/link interop vs SDK fake
VM), `v0.4-ondevice-logcat.txt` (install/start/SELFTEST run on the
Shield). v0.3 and earlier: `bt_manager_dump.txt` (pre-test),
`bt_manager_during_advertising.txt` (v0.1 run — its logcat lines,
including the DATA_TOO_LARGE failure, are quoted in the findings
above; `logcat_prototype_test.txt` holds a later run's tail),
`bt_manager_v02_during.txt`
(GATT-server + scanner registration), `logcat_v02_full.txt` (named
advertising success), `logcat_v03_micprobe.txt` (full mic sweep).
Test harnesses live in `tests/` (`VectorMain`, `LoopbackDevice`,
`phone_loopback.py`, `fake_vm.py`, `LinkMain`, `link_interop.py`,
`ws_bridge.py`).
