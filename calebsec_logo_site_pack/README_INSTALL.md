# CalebSec Logo Site Pack

## What is included

```text
static/calebsec-logo.png
static/logo.css
docs/logo_html_snippet.html
```

## How to add it in GitHub

1. Go to your CalebSec repo.
2. Switch to your `soc-upgrade` branch.
3. Upload the `static/calebsec-logo.png` file into your existing `static/` folder.
4. Upload `static/logo.css` into your existing `static/` folder.

## Add the logo to your dashboard

Open:

```text
templates/dashboard.html
```

Find the top-left CalebSec brand/header area.

Add this:

```html
<img src="/static/calebsec-logo.png" alt="CalebSec Logo" class="site-logo">
```

## Add the CSS

If your dashboard already links CSS files, add this inside the `<head>` section:

```html
<link rel="stylesheet" href="/static/logo.css">
```

If you do not want to add a CSS file, paste this inside the existing `<style>` block:

```css
.site-logo {
  height: 56px;
  width: auto;
  object-fit: contain;
  display: block;
}

.hero-logo {
  max-width: 420px;
  width: 100%;
  height: auto;
  display: block;
  margin-bottom: 24px;
}
```

## Optional hero placement

If you want the larger logo inside the main dashboard card, add:

```html
<img src="/static/calebsec-logo.png" alt="CalebSec Security Operations Platform Logo" class="hero-logo">
```

## Commit message

```text
Add CalebSec logo to site
```
