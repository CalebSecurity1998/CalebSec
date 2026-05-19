# Safe GitHub Update Commands

Run these from your project folder.

## 1. Make sure you are on the SOC upgrade branch

```bash
cd ~/mini-siem
git branch
```

If needed:

```bash
git checkout soc-upgrade
```

## 2. Copy this package into your repo

Copy these into the root of your repository:

```text
README.md
docs/
screenshots/
.github/
```

## 3. Check what changed

```bash
git status
```

## 4. Add the documentation package

```bash
git add README.md docs screenshots .github
```

## 5. Commit

```bash
git commit -m "Add GitHub portfolio documentation"
```

## 6. Push

```bash
git push origin soc-upgrade
```

## 7. Open a Pull Request

On GitHub, open:

```text
soc-upgrade → main
```

Review everything before merging.
