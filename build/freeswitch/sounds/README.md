# HAL Audio Provenance

These WAV files are generated assets for the `pbx2` FreeSWITCH Lua SQL injection demo.

- Source workflow: `scripts/generate_hal_audio.sh`
- Generation method: synthetic text-to-speech output
- Current provider used by the script: ElevenLabs
- Voice ID: private account-scoped HAL-style voice
- Required regeneration inputs: `ELEVENLABS_API_KEY`, `curl`, `file`, and `sox`

The tracked `hal_intro.wav`, `hal_quote_1.wav`, and `hal_access_granted.wav`
files are produced by the generation script and converted to 8 kHz mono 16-bit
PCM WAV so FreeSWITCH can play them directly.

To regenerate them:

```bash
ELEVENLABS_API_KEY=your_key ./scripts/generate_hal_audio.sh
```
