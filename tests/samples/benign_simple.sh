#!/bin/sh
# Simple installer: puts a tiny script in ~/.local/bin. No root needed.
set -eu

echo "Installing hello to ~/.local/bin (no sudo needed)"
mkdir -p "$HOME/.local/bin"

cat > "$HOME/.local/bin/hello" <<'SCRIPT'
#!/bin/sh
echo "hello from a harmless test script"
SCRIPT

chmod 755 "$HOME/.local/bin/hello"   # normal permissions, not setuid
echo "Done. Run: hello"
