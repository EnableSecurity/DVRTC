#!/bin/bash
#
# Generate HAL-style audio clips for the FreeSWITCH Lua SQLi demo using ElevenLabs.
# Output: 8kHz mono 16-bit PCM WAV files for FreeSWITCH playback.
#
# Usage:
#   ELEVENLABS_API_KEY=your_key ./scripts/generate_hal_audio.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../build/freeswitch/sounds"
HAL_VOICE_ID="${ELEVENLABS_HAL_VOICE_ID:-EQEAJ5VgvYg7h3cIcWKT}"
ELEVENLABS_MODEL_ID="${ELEVENLABS_MODEL_ID:-eleven_multilingual_v2}"

if [ -z "${ELEVENLABS_API_KEY:-}" ]; then
    echo "ERROR: ELEVENLABS_API_KEY environment variable is not set" >&2
    exit 1
fi

for cmd in curl sox file; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: $cmd is required but not installed" >&2
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"

generate_clip() {
    local name="$1"
    local text="$2"
    local output_mp3="${OUTPUT_DIR}/${name}.mp3"
    local output_wav="${OUTPUT_DIR}/${name}.wav"

    echo "Generating ${name}..."

    curl -s -X POST "https://api.elevenlabs.io/v1/text-to-speech/${HAL_VOICE_ID}" \
        -H "xi-api-key: ${ELEVENLABS_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{
            \"text\": \"${text}\",
            \"model_id\": \"${ELEVENLABS_MODEL_ID}\",
            \"voice_settings\": {
                \"stability\": 0.72,
                \"similarity_boost\": 0.86,
                \"style\": 0.18,
                \"use_speaker_boost\": true
            }
        }" \
        -o "$output_mp3"

    if [ ! -s "$output_mp3" ] || file "$output_mp3" | grep -qi "text\|json\|html"; then
        echo "[error] Failed to generate ${name} - API returned non-audio response:" >&2
        cat "$output_mp3" >&2 || true
        rm -f "$output_mp3"
        return 1
    fi

    sox "$output_mp3" -r 8000 -c 1 -b 16 -e signed-integer "$output_wav"
    rm -f "$output_mp3"
    echo "[done] ${name}.wav"
}

generate_clip "hal_intro" \
    "Good evening. This is the HAL 9000 computer aboard the United States Spacecraft Discovery One. I am attempting to connect you to extension 2001. Please stand by."

generate_clip "hal_quote_1" \
    "I'm sorry, Dave. I'm afraid I can't do that."

generate_clip "hal_access_granted" \
    "Access granted. Hello, Dave. You are now in control of the Discovery."

echo "Generated HAL audio clips in ${OUTPUT_DIR}"