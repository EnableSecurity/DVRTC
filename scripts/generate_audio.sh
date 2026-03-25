#!/bin/bash
#
# Generate realistic audio clips for RTP bleed demo using ElevenLabs TTS API.
# Output: 8kHz mono 16-bit PCM WAV files (required by baresip PCMU/PCMA codecs).
#
# Prerequisites:
#   - ELEVENLABS_API_KEY environment variable set
#   - sox installed (for format conversion): apt-get install sox libsox-fmt-all
#   - curl installed
#
# Usage:
#   ELEVENLABS_API_KEY=your_key ./scripts/generate_audio.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../build/baresip-callgen/sounds"

if [ -z "${ELEVENLABS_API_KEY:-}" ]; then
    echo "ERROR: ELEVENLABS_API_KEY environment variable is not set"
    echo "Get an API key at https://elevenlabs.io"
    exit 1
fi

for cmd in curl sox; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not installed"
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"

# ElevenLabs voice IDs. Override these if your account exposes different defaults.
VOICE_RACHEL="${ELEVENLABS_VOICE_RACHEL:-21m00Tcm4TlvDq8ikWAM}"  # Rachel
VOICE_ADAM="${ELEVENLABS_VOICE_ADAM:-pNInz6obpgDQGcFmaJgB}"      # Adam
ELEVENLABS_MODEL_ID="${ELEVENLABS_MODEL_ID:-eleven_multilingual_v2}"

generate_clip() {
    local name="$1"
    local voice_id="$2"
    local text="$3"
    local output_mp3="${OUTPUT_DIR}/${name}.mp3"
    local output_wav="${OUTPUT_DIR}/${name}.wav"

    if [ -f "$output_wav" ]; then
        echo "  [skip] ${name}.wav already exists"
        return 0
    fi

    echo "  Generating ${name}..."

    curl -s -X POST "https://api.elevenlabs.io/v1/text-to-speech/${voice_id}" \
        -H "xi-api-key: ${ELEVENLABS_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{
            \"text\": \"${text}\",
            \"model_id\": \"${ELEVENLABS_MODEL_ID}\",
            \"voice_settings\": {
                \"stability\": 0.5,
                \"similarity_boost\": 0.75
            }
        }" \
        -o "$output_mp3"

    # Check if we got a valid audio file
    if [ ! -s "$output_mp3" ] || file "$output_mp3" | grep -qi "text\|json\|html"; then
        echo "  [error] Failed to generate ${name} - API returned non-audio response:"
        cat "$output_mp3"
        rm -f "$output_mp3"
        return 1
    fi

    # Convert to 8kHz mono 16-bit PCM WAV (required by baresip)
    sox "$output_mp3" -r 8000 -c 1 -b 16 -e signed-integer "$output_wav"
    rm -f "$output_mp3"

    echo "  [done] ${name}.wav ($(du -h "$output_wav" | cut -f1))"
}

echo "Generating audio clips for RTP bleed demo..."
echo "Output directory: ${OUTPUT_DIR}"
echo ""

# Clip 1: Credit card / SSN readback
generate_clip "conversation1" "$VOICE_RACHEL" \
    "Okay, I've pulled up your account. Let me verify your information. Your card number ending in 4 8 7 2, correct? And I have your social security number on file as 4 5 6, 7 8, 9 0 1 2. The billing address is 1 4 2 Oak Street, Springfield. Now for the refund, that will go back to the Visa ending in 4 8 7 2. The amount is three hundred forty seven dollars and sixty two cents. You should see it in three to five business days. Is there anything else I can help you with today?"

# Clip 2: Confidential business discussion
generate_clip "conversation2" "$VOICE_ADAM" \
    "Listen, this cannot leave this call. The board is planning to announce the acquisition next Thursday. We're buying Meridian Systems for two hundred and forty million. Stock price will definitely move once it's public. Legal wants everyone to sign the NDA before end of day. The due diligence team found some issues with their European contracts but nothing that would kill the deal. We need to keep this absolutely quiet until the press release goes out. Can you make sure the integration team is ready to move on day one?"

# Clip 3: Customer support with account details
generate_clip "conversation3" "$VOICE_ADAM" \
    "Thank you for calling Premier Financial Services. I have your account open, Mr. Henderson. Your current balance is fourteen thousand, two hundred and thirty one dollars. I see you have a pending wire transfer for eight thousand five hundred to account number 7 7 2 0 4 8 3 9 1 at First National Bank. The routing number is 0 2 1 0 0 0 0 8 9. That transfer is scheduled for tomorrow morning. Your monthly statement will also show the automatic payment to your mortgage of two thousand, one hundred and fifty dollars."

# Clip 4: Medical information
generate_clip "conversation4" "$VOICE_RACHEL" \
    "Hi, this is Doctor Patel's office calling about your lab results. Your blood work came back and we need to discuss a few things. Your cholesterol is at two forty two which is higher than we'd like. The prescription for Atorvastatin has been called in to your pharmacy at Walgreens on Main Street. Your date of birth we have on file is March fifteenth, nineteen seventy eight and your patient ID is P H dash nine four seven two one. Please call us back at your earliest convenience to schedule a follow up appointment."

echo ""
echo "Audio generation complete!"
echo "Files in ${OUTPUT_DIR}:"
ls -la "${OUTPUT_DIR}"/*.wav 2>/dev/null || echo "  (no files generated)"
