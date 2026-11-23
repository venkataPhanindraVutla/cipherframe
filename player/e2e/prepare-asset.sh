#!/bin/sh
# Makes a short test video, uploads it through the API and waits until the asset is ready.
# Prints the asset ID on stdout (everything else goes to stderr). Needs curl and jq.
#
#   CIPHERFRAME_API_KEY    an API key with assets:write (read from the environment, never an argument)
#   FIXTURE_FFMPEG         the test-only FFmpeg with lavfi (build/worker.Dockerfile, target `tools`)
#   CIPHERFRAME_API_URL    default http://127.0.0.1:8080
#   CIPHERFRAME_EXTRA_CODECS  optional, for example "hevc av1" (needs the admin scope): turns those extra
#                          codecs on for the tenant first, so the asset has a multi-codec master (ADR 0064)
set -eu

api="${CIPHERFRAME_API_URL:-http://127.0.0.1:8080}"
: "${CIPHERFRAME_API_KEY:?set CIPHERFRAME_API_KEY}"
: "${FIXTURE_FFMPEG:?set FIXTURE_FFMPEG}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 40 seconds of colour bars with a tone, 2 second GOPs: long enough to cross several heartbeats.
"$FIXTURE_FFMPEG" -hide_banner -loglevel error \
	-f lavfi -i "testsrc2=size=640x360:rate=24:duration=40" \
	-f lavfi -i "sine=frequency=440:sample_rate=48000:duration=40" \
	-c:v libx264 -preset ultrafast -pix_fmt yuv420p -g 48 -c:a aac -b:a 64k -ac 2 \
	-f mp4 "file:$work/in.mp4"
size="$(wc -c <"$work/in.mp4" | tr -d ' ')"
echo "test video: $size bytes" >&2

auth="Authorization: Bearer ${CIPHERFRAME_API_KEY}"

# The worker reports its codecs when it starts, and the setting is refused until it has, so retry for a minute.
if [ -n "${CIPHERFRAME_EXTRA_CODECS:-}" ]; then
	codecs="$(printf '%s' "$CIPHERFRAME_EXTRA_CODECS" | jq -Rc 'split(" ") | map(select(. != ""))')"
	done_=""
	for _ in $(seq 1 30); do
		settings="$(curl -fsS -H "$auth" "$api/v1/playback-settings" | jq -c --argjson c "$codecs" 'del(.updated_at) | .extra_codecs = $c')"
		if curl -fsS -X PUT -H "$auth" -H 'Content-Type: application/json' -d "$settings" "$api/v1/playback-settings" >/dev/null 2>&1; then
			done_=1
			break
		fi
		sleep 2
	done
	[ -n "$done_" ] || { echo "the extra codecs ($CIPHERFRAME_EXTRA_CODECS) were not accepted: is a worker running with them?" >&2; exit 1; }
fi
created="$(curl -fsS -H "$auth" -H 'Content-Type: application/json' \
	-d "{\"size_bytes\":${size},\"upload_method\":\"multipart\",\"content_type\":\"video/mp4\"}" "$api/v1/assets")"
asset="$(echo "$created" | jq -r .asset.id)"
url="$(echo "$created" | jq -r .upload.url)"
token="$(echo "$created" | jq -r .upload.token)"
test "$(wc -c <"$work/in.mp4")" -le "$(echo "$created" | jq -r '.upload.part_size_bytes')" # one part

curl -fsS -X PUT -H "Authorization: Bearer ${token}" --data-binary "@$work/in.mp4" "${url}1" >/dev/null
curl -fsS -X POST -H "$auth" "$api/v1/assets/${asset}/commit" >/dev/null

for _ in $(seq 1 150); do
	state="$(curl -fsS -H "$auth" "$api/v1/assets/${asset}" | jq -r .state)"
	[ "$state" = ready ] && { echo "$asset"; exit 0; }
	[ "$state" = failed ] && { echo "asset processing failed" >&2; exit 1; }
	sleep 2
done
echo "asset not ready after 5 minutes (state: $state)" >&2
exit 1
