# Audio Provenance

These WAV files are generated assets for the RTP bleed demo.

- Source workflow: `scripts/generate_audio.sh`
- Generation method: synthetic text-to-speech output
- Current provider used by the script: ElevenLabs
- Required regeneration inputs: `ELEVENLABS_API_KEY`, `curl`, `file`, and `sox`

The tracked `conversation*.wav` files were produced by running the generation
script and converting the result to 8 kHz mono 16-bit PCM WAV so baresip can
play them during the call generator scenario.

The dialog content is synthetic demo material intended to sound sensitive so
the RTP bleed exercise has realistic audio to recover. These files are not
captured phone calls.

To regenerate them:

```bash
ELEVENLABS_API_KEY=your_key ./scripts/generate_audio.sh
```

The generator skips existing `.wav` files, so remove a clip first if you want to recreate it.

When updating these assets, keep the output format compatible with
`build/baresip-callgen/config` and avoid replacing them with third-party
recordings that have unclear reuse rights.
