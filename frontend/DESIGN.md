---
name: Terminal Protocol
colors:
  surface: '#121414'
  surface-dim: '#121414'
  surface-bright: '#37393a'
  surface-container-lowest: '#0c0f0f'
  surface-container-low: '#1a1c1c'
  surface-container: '#1e2020'
  surface-container-high: '#282a2b'
  surface-container-highest: '#333535'
  on-surface: '#e2e2e2'
  on-surface-variant: '#c4c9ac'
  inverse-surface: '#e2e2e2'
  inverse-on-surface: '#2f3131'
  outline: '#8e9379'
  outline-variant: '#444933'
  surface-tint: '#abd600'
  primary: '#ffffff'
  on-primary: '#283500'
  primary-container: '#c3f400'
  on-primary-container: '#556d00'
  inverse-primary: '#506600'
  secondary: '#c8c6c5'
  on-secondary: '#313030'
  secondary-container: '#474746'
  on-secondary-container: '#b7b5b4'
  tertiary: '#ffffff'
  on-tertiary: '#303030'
  tertiary-container: '#e4e2e1'
  on-tertiary-container: '#656464'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#c3f400'
  primary-fixed-dim: '#abd600'
  on-primary-fixed: '#161e00'
  on-primary-fixed-variant: '#3c4d00'
  secondary-fixed: '#e5e2e1'
  secondary-fixed-dim: '#c8c6c5'
  on-secondary-fixed: '#1c1b1b'
  on-secondary-fixed-variant: '#474746'
  tertiary-fixed: '#e4e2e1'
  tertiary-fixed-dim: '#c8c6c6'
  on-tertiary-fixed: '#1b1c1c'
  on-tertiary-fixed-variant: '#474747'
  background: '#121414'
  on-background: '#e2e2e2'
  surface-variant: '#333535'
typography:
  display-lg:
    fontFamily: Bebas Neue
    fontSize: 96px
    fontWeight: '400'
    lineHeight: '1.0'
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Bebas Neue
    fontSize: 64px
    fontWeight: '400'
    lineHeight: '1.1'
  headline-lg-mobile:
    fontFamily: Bebas Neue
    fontSize: 48px
    fontWeight: '400'
    lineHeight: '1.1'
  headline-md:
    fontFamily: Bebas Neue
    fontSize: 32px
    fontWeight: '400'
    lineHeight: '1.2'
  body-lg:
    fontFamily: JetBrains Mono
    fontSize: 16px
    fontWeight: '400'
    lineHeight: '1.6'
  body-md:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '400'
    lineHeight: '1.5'
  label-code:
    fontFamily: Space Mono
    fontSize: 12px
    fontWeight: '700'
    lineHeight: '1.0'
  label-prefix:
    fontFamily: Space Mono
    fontSize: 14px
    fontWeight: '400'
    lineHeight: '1.0'
spacing:
  unit: 4px
  gutter: 16px
  margin-mobile: 16px
  margin-desktop: 40px
  grid-size: 32px
---

## Brand & Style

The design system is rooted in **Cyber Brutalism**—a raw, digital-first aesthetic that prioritizes systematic function over decorative polish. It is designed for deep packet inspection and network security professionals who value high-density information and technical transparency.

The visual narrative is "Machine-First." It utilizes high-contrast interfaces, grid-based alignment, and glitch-inspired textures to evoke a sense of urgent, real-time monitoring. The interface is unapologetically functional, treating every pixel as a data point. The emotional response is one of precision, authority, and uncompromising security.

## Colors

This design system uses a **pure black (#000000) base** to maximize the luminance of its neon accents. The primary color is a high-visibility **Neon Green**, used exclusively for interactive elements, status indicators, and critical data highlights. 

- **Primary:** High-contrast neon for calls to action and "active" states.
- **Surface:** Deep grays are used to create subtle container differentiation without breaking the monolithic black feel.
- **Accents:** Occasional high-alert red is reserved for security breaches and critical system failures.
- **Text:** Pure white for high legibility, with primary green used for specific technical labels and headers.

## Typography

Typography is the core structural element of this design system. It utilizes a striking contrast between **Bebas Neue** for large, impactful headers and **JetBrains Mono** for all technical and body data.

- **Headers:** Always uppercase, tightly tracked, and condensed.
- **Data/Body:** Monospaced for perfect vertical alignment of numbers and logs.
- **Prefixes:** Use `/01`, `/02` prefixes in Neon Green before section headers to reinforce the systematic, indexed nature of the tool.
- **Code Blocks:** Use absolute monospacing for log outputs to ensure visual scanning of network packets is seamless.

## Layout & Spacing

The layout is governed by a **strict 12-column grid** that is often visually exposed via thin 1px lines or dot-matrix overlays.

- **Fluidity:** The grid is fluid, but content containers are often separated by hard 1px borders rather than whitespace.
- **Density:** Information density is high. Use a 4px baseline shift for tight grouping of related technical metrics.
- **Structure:** Align elements to a 32px vertical rhythm. Use "plus" (+) symbols at the intersections of grid lines to emphasize the structural skeleton.
- **Breakpoints:** On mobile, the 12-column grid collapses to a single column, but maintaining 1px borders between vertical sections is mandatory to preserve the Brutalist aesthetic.

## Elevation & Depth

This design system rejects traditional shadows and soft blurs. Depth is communicated through **flat stacking** and **high-contrast outlines**.

- **Stacking:** Elements do not "float"; they are "layered." Use 1px solid borders in Neon Green or Medium Gray to define container boundaries.
- **Textures:** Use scanlines (0.1 opacity) or fine grid overlays to differentiate the background from the foreground "active" workspace.
- **Focus States:** Active containers should glow slightly with a 1px solid Neon Green border and a subtle inner-glow (box-shadow: 0 0 10px rgba(204, 255, 0, 0.3)).

## Shapes

The shape language is **strictly geometric and sharp**. There are no rounded corners in this design system. 

- **Containers:** All containers, buttons, and input fields must have a 0px border radius.
- **Angled Accents:** Use 45-degree clipped corners (chamfers) for decorative UI elements or "Action" buttons to provide a military-grade hardware feel.
- **Dividers:** Use 1px vertical and horizontal lines. Never use soft gradients to separate content.

## Components

### Buttons
- **Primary:** Solid Neon Green background, black text (Bebas Neue). Always include a 45-degree arrow icon (↗) in the top right.
- **Secondary:** Transparent background, 1px Neon Green border, Neon Green text.
- **Hover State:** Inverse colors or "glitch" shift (2px horizontal offset for 50ms).

### Input Fields
- Underlined style only (1px gray border-bottom) or fully boxed with a technical label in the top-left corner (e.g., `> INPUT_USER`).
- Text cursor should be a solid block (█) to mimic terminal environments.

### Hazard Footer
- The footer must feature a **Hazard Tape** pattern: alternating 45-degree diagonal stripes of Neon Green and Black. 
- Content within the footer should be monospaced and center-aligned.

### Data Chips
- Small, rectangular blocks with labels like `[ STATUS: OK ]`. Use square brackets to enclose metadata.

### System Indicators
- Small uppercase labels prefixed with a slash and number (e.g., `/04 SYSTEM_STATUS`) serve as section anchors.
- Use simple ASCII-style progress bars for CPU/Network load (e.g., `||||||||||||||||| 70%`).