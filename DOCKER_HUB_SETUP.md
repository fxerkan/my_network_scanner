# 🐳 Docker Hub Setup Instructions

## Overview Setup for Docker Hub Repository

This document contains instructions for setting up the Docker Hub repository for My Network Scanner.

## 1. Repository Overview

The content from `DOCKER_README.md` should be used as the Docker Hub repository overview. To set this up:

1. Go to [Docker Hub](https://hub.docker.com)
2. Navigate to your repository: `fxerkan/my_network_scanner`
3. Click on "Settings" or "Manage Repository"
4. In the "Repository Description" section, paste the contents of `DOCKER_README.md`
5. Save the changes

## 2. Repository Logo/Avatar

Use the generated logo files for the repository avatar:

### Option A: Use SVG (Recommended)
- Upload `assets/logo_large.svg` (512x512) as the repository avatar
- This provides the best quality at all sizes

### Option B: Use PNG (Alternative)
1. Convert `assets/logo_large.svg` to PNG using:
   - Online converter: https://convertio.co/svg-png/
   - ImageMagick: `convert assets/logo_large.svg -resize 512x512 assets/logo_512x512.png`
2. Upload the PNG file as repository avatar

## 3. Repository Settings

Configure these settings in Docker Hub:

### General
- **Repository Name**: `my_network_scanner`
- **Visibility**: Public
- **Short Description**: "Your Family's User-Friendly Network Scanner - Comprehensive LAN scanner with web interface"

### Builds (if using automated builds)
- **Source Repository**: `https://github.com/fxerkan/my_network_scanner`
- **Dockerfile Location**: `/Dockerfile`
- **Build Rules**:
  - Source Type: Tag
  - Source: `/^v[0-9.]+$/`
  - Docker Tag: `{sourceref}`
  - Autobuild: ✓

### Collaborators
- Add any team members who need access

## 4. Tags and Versioning

Recommended tagging strategy:
- `latest` - Always points to the most recent stable version
- `v1.0.4` - Specific version tags
- `stable` - Latest stable release
- `dev` - Development/testing builds

## 5. README Content

The Docker Hub overview should include:

✅ **Already included in DOCKER_README.md:**
- Project description with emoji
- Quick start instructions (Docker Compose + Docker Run)
- Feature list with icons
- Advanced capabilities
- Security requirements
- Supported architectures
- Environment variables
- Volume mounts
- Links to GitHub and documentation

## 6. Social Links

Add these links in Docker Hub settings:
- **Homepage**: `https://github.com/fxerkan/my_network_scanner`
- **Documentation**: `https://github.com/fxerkan/my_network_scanner/blob/main/CLAUDE.md`
- **Issues**: `https://github.com/fxerkan/my_network_scanner/issues`

## 7. GitHub Social Preview

For GitHub repository social preview:
1. Go to GitHub repository Settings
2. Scroll to "Social preview"
3. Upload `assets/logo_large.svg` or convert to PNG (1280x640 recommended)
4. This appears when the repo is shared on social media

## 8. Badges and Shields

Add these badges to README files:

```markdown
[![Docker Hub](https://img.shields.io/docker/pulls/fxerkan/my_network_scanner.svg)](https://hub.docker.com/r/fxerkan/my_network_scanner)
[![Docker Image Size](https://img.shields.io/docker/image-size/fxerkan/my_network_scanner/latest)](https://hub.docker.com/r/fxerkan/my_network_scanner)
[![GitHub Release](https://img.shields.io/github/v/release/fxerkan/my_network_scanner)](https://github.com/fxerkan/my_network_scanner/releases)
[![License](https://img.shields.io/github/license/fxerkan/my_network_scanner)](LICENSE)
```

## 9. Automated Builds

If using GitHub Actions for automated builds:

1. Set up Docker Hub access tokens
2. Add secrets to GitHub repository:
   - `DOCKERHUB_USERNAME`
   - `DOCKERHUB_TOKEN`
3. Use the existing GitHub Actions workflow
4. Tag releases in GitHub to trigger builds

## 10. Verification

After setup, verify:
- [ ] Repository overview displays correctly
- [ ] Logo appears as repository avatar
- [ ] Tags are properly organized
- [ ] Build hooks work (if automated)
- [ ] Links in description work
- [ ] Social preview looks good

---

**Note**: Some changes may take a few minutes to appear on Docker Hub due to caching.