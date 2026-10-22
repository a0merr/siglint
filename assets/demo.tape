# VHS tape — generates assets/demo.gif for the README.
# Install VHS (https://github.com/charmbracelet/vhs), then from the repo root:
#   pip install -e .
#   vhs assets/demo.tape
# Output lands at assets/demo.gif.

Output assets/demo.gif

Set Shell "powershell"
Set FontSize 16
Set Width 1200
Set Height 500
Set Theme "Dracula"
Set Padding 24
Set TypingSpeed 45ms

Hide
Type "function prompt { '$ ' }; if (-not (Get-Command siglint -EA 0)) { function siglint { python -m siglint.cli @args } }; cls"
Enter
Show

# A real Sigma rule: selection minus a filter.
Type "cat rules/sudo_abuse.yml"
Enter
Sleep 3s

Type "siglint validate rules"
Enter
Sleep 2s

Hide
Type "cls"
Enter
Show

# Two logs, one pass; exit 1 gates CI on anything high or worse.
Type "siglint scan examples/auth.log examples/process_web.log -r rules --fail-on high"
Enter
Sleep 3500ms

Type "echo exit=$LASTEXITCODE"
Enter
Sleep 3s
