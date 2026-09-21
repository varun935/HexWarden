import os
import glob
import re

html_dir = "/Users/socratic/Code/SIH/HexWarden/web/templates"
files = glob.glob(os.path.join(html_dir, "*.html"))

lenis_block = """
  <!-- Lenis for smooth scrolling -->
  <script src="https://unpkg.com/@studio-freight/lenis@1.0.34/dist/lenis.min.js"></script>
  <script>
    if (typeof Lenis !== 'undefined') {
      const lenis = new Lenis({
        duration: 1.2,
        easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
        direction: 'vertical',
        gestureDirection: 'vertical',
        smooth: true,
        mouseMultiplier: 1,
        smoothTouch: false,
        touchMultiplier: 2,
        infinite: false,
      });

      function raf(time) {
        lenis.raf(time);
        requestAnimationFrame(raf);
      }

      requestAnimationFrame(raf);
    }
  </script>
</body>"""

for f in files:
    if f.endswith("_nav.html"):
        continue
    with open(f, "r") as file:
        content = file.read()
    
    # Clean any previously injected Lenis blocks and <script> tags
    content = re.sub(r'[ \t]*<!-- Lenis for smooth scrolling -->[\s\S]*?(?=</body>)', '', content)
    
    # Inject before </body>
    if '</body>' in content:
        content = content.replace('</body>', lenis_block)
        with open(f, "w") as file:
            file.write(content)
        print(f"Updated {os.path.basename(f)}")
