#!/usr/bin/env bash
# Build the marketplace zip: SKILL.md at the root, plus scripts/ and references/.
# Runs the tests first and refuses to package if they fail.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

name=$(sed -n 's/^name: *//p' SKILL.md | head -1)
[ -n "$name" ] || { echo "SKILL.md has no name in its frontmatter" >&2; exit 1; }
grep -q '^description: .\{20,\}' SKILL.md || { echo "SKILL.md needs a description" >&2; exit 1; }

bash tests/run.sh > /dev/null || { echo "tests failed, not packaging" >&2; exit 1; }

mkdir -p dist
out="dist/$name.zip"
rm -f "$out"
zip -q -r "$out" SKILL.md LICENSE scripts references -x '*.swp' '*~'
echo "built $out"
unzip -l "$out"
