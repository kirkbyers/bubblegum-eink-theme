# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Visual Studio Code color theme extension called "Bubblegum E-Ink Theme" that provides an e-ink like appearance with pops of bubblegum color. The theme is designed to be easy on the eyes with a light background similar to e-ink displays.

## Development Commands

### Testing the Theme
- Press `F5` to open a new Extension Development Host window with the theme loaded
- Open the color theme picker: `File > Preferences > Theme > Color Theme` or `Ctrl+K Ctrl+T` (Windows/Linux) / `Cmd+K Cmd+T` (Mac)
- Select "Bubblegum E-Ink" to preview the theme
- Use `Developer: Inspect Editor Tokens and Scopes` command (`Ctrl+Shift+P` / `Cmd+Shift+P`) to examine token scopes for theme development

### Installation
- Copy the extension folder to `<user home>/.vscode/extensions` and restart VS Code

## File Structure

```
├── package.json                           # Extension manifest
├── themes/
│   └── Bubblegum E-Ink-color-theme.json  # Theme definition file
├── inspo/
│   └── solarized-light.jsonc             # Inspiration/reference theme
└── vsc-extension-quickstart.md           # VS Code extension quickstart guide
```

## Theme Architecture

The theme follows the VS Code color theme structure:
- `colors`: Defines UI element colors (editor background, foreground, etc.)
- `tokenColors`: Defines syntax highlighting colors mapped to TextMate scopes

### Key Theme Features
- Light e-ink style background (`#f5f5f5`)
- Dark text for readability (`#333333`)
- Bubblegum accent colors for syntax highlighting
- Specific color mappings for different language constructs (comments, keywords, strings, etc.)

### Color Palette
- Background: `#f5f5f5` (light gray)
- Foreground: `#333333` (dark gray)
- Comments: `#AAAAAA` (light gray, italic)
- Keywords: `#4B83CD` (blue)
- Strings: `#448C27` (green)
- Functions: `#AA3731` (red, bold)
- Types/Classes: `#7A3E9D` (purple, bold)

Changes to the theme file are automatically applied to the Extension Development Host window during development.