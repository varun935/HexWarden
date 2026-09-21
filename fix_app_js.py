import os

filepath = "/Users/socratic/Code/SIH/HexWarden/web/templates/about.html"
with open(filepath, "r") as f:
    content = f.read()

if "app.js" not in content:
    lenis_marker = "<!-- Lenis for smooth scrolling -->"
    app_js_script = "<script src=\"{{ url_for('static', filename='app.js') }}\" defer></script>\n  "
    content = content.replace(lenis_marker, app_js_script + lenis_marker)
    with open(filepath, "w") as f:
        f.write(content)
        print("Added app.js to about.html")
