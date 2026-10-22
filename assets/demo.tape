# VHS tape — generates assets/demo.gif for the README.
# Install VHS (https://github.com/charmbracelet/vhs), then from the repo root:
#   pip install -e .
#   vhs assets/demo.tape
# Output lands at assets/demo.gif.

Output assets/demo.gif

Set FontSize 16
Set Width 1100
Set Height 700
Set Theme "Dracula"
Set Padding 24

Type "siglint scan examples/auth.log -r rules"
Enter
Sleep 2500ms

Type "siglint scan examples/process_web.log -r rules"
Enter
Sleep 2500ms

Type "siglint scan examples/auth.log -r rules --fail-on high -o json"
Enter
Sleep 3s
