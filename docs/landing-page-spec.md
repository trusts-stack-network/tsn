# Technical Specification - TSN Landing Page

## Table of Contents
1. [Vue d'ensemble](#vue-densemble)
2. [Architecture Technique](#architecture-technique)
3. [Structure of the Sections](#structure-des-sections)
4. [Specifications Responsive](#specifications-responsive)
5. [Performance & Optimisation](#performance--optimisation)
6. [References](#references)

## Overview

### Objective
Development of the main landing page for **Trust Stack Network (TSN)** - distributed trust decentralized platform. Responsive showcase interface presenting the project vision, technology, team, and roadmap.

### Technical Stack
- **HTML5** semantic, validated W3C
- **CSS3** with variables CSS (custom properties)
- **Vanilla JavaScript** (ES6+), no external dependencies
- **Assets** : SVG optimizeds, WebP/AVIF with fallbacks
- **Hosting** : Static CDN (Cloudflare/Netlify)

### Constraints
- Lighthouse score > 95 (Performance, Accessibility, SEO)
- Temps de chargement initial < 1.5s (3G)
- Compatibility : Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- No external CSS/JS library (zero-dependency)

## Technical Architecture

### File Structure
tsn-landing/
├── index.html
├── assets/
│   ├── css/
│   │   ├── main.css          # Styles globto & variables
│   │   ├── sections.css      # Styles specifics sections
│   │   └── responsive.css    # Media queries
│   ├── js/
│   │   ├── main.js           # Initialization & utilities
│   │   ├── animations.js     # IntersectionObserver & transitions
│   │   └── navigation.js     # Smooth scroll & mobile menu
│   └── images/
│       ├── hero/             # Images hero (responsive srcset)
│       ├── team/             # Team photos (WebP)
│       └── icons/            # SVG sprites
└── docs/                     # Documentation technique

### Architecture Diagram flux data
```mermaid
graph TD
    A[Client Browser] --> B[index.html]
    B --> C[Critical CSS Inline]
    B --> D[Async CSS Load]
    B --> E[Defer JS Bundle]
    
    E --> F[main.js]
    F --> G[IntersectionObserver]
    F --> H[Animation Controller]
    F --> I[Navigation Handler]
    
    G --> J[Lazy Load Images]
    H --> K[Scroll Reveal Effects]
    I --> L[Mobile Menu Toggle]
    
    style C fill:#f9f,stroke:#333,stroke-width:2px
    style E fill:#bbf,stroke:#333,stroke-width:2px

### CSS Variables (Design System)
:root {
  /* TSN Brand Colors */
  --tsn-primary: #0A192F;        /* Deep Navy */
  --tsn-secondary: #64FFDA;      /* Cyber Teal */
  --tsn-accent: #FF6B6B;         /* Alert Coral */
  --tsn-text-primary: #E6F1FF;   /* Off White */
  --tsn-text-secondary: #8892B0; /* Slate */
  
  /* Typography */
  --font-mono: 'Fira Code', 'Consolas', monospace;
  --font-sans: 'Inter', -apple-system, sans-serif;
  --font-display: 'Cal Sans', 'Inter', sans-serif;
  
  /* Spacing Scale (8px base) */
  --space-xs: 0.5rem;   /* 8px */
  --space-sm: 1rem;     /* 16px */
  --space-md: 2rem;     /* 32px */
  --space-lg: 4rem;     /* 64px */
  --space-xl: 8rem;     /* 128px */
  
  /* Animation */
  --transition-fast: 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  --transition-medium: 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  --transition-slow: 0.8s cubic-bezier(0.4, 0, 0.2, 1);
}

## Section Structure

### 1. Hero Section
**ID**: `#hero`  
**Height**: 100vh (viewport full)  
**Content**:
- Logo TSN animated (SVG morphing)
- Tagline: "Distributed Trust Infrastructure"
- Primary CTA: "Explore the Documentation" → `/docs`
- Secondary CTA: "Watch the Demo" → Modal video
- Background: Mesh gradient animated (Canvas 2D, fallback CSS gradient)

**Technical Specifications**:
- Preload of the font-display critical
- Canvas background with detection `prefers-reduced-motion`
- Light parallax sur le tagline (translateY at scroll)

### 2. Vision Section
**ID**: `#vision`  
**Layout**: Grid 2 colonnes (texte | illustration)  
**Content**:
- Titre: "Rebuilding Digital Trust"
- 3 pillars (cards): Decentralization, Verification, Sovereignty
- Key Statistics (animated counters)

**Animation**:
- Stagger reveal on cards (delay 100ms between each)
- Compteurs: `requestAnimationFrame` pour performance 60fps

### 3. Tech Stack Section
**ID**: `#technology`  
**Layout**: Tabs interactives horizontales  
**Content**:
- Architecture: Blockchain layer, Consensus mechanism, Cryptographic primitives
- Code snippets syntax-highlighted (prism.js-like custom lightweight)
- Diagramme architecture technique (SVG interactif)

**Components JS**:
class TechTabs {
  constructor(container) {
    this.tabs = container.querySelectorAll('[data-tab]');
    this.panels = container.querySelectorAll('[data-panel]');
    this.init();
  }
  
  // aria-selected management, CSS transitions
}

### 4. Team Section
**ID**: `#team`  
**Layout**: Grid responsive (1 col mobile → 4 col desktop)  
**Content**:
- Team photos (square format, ratio 1:1)
- Nom, role, liens socito (GitHub, Twitter, LinkedIn)
- Short bio (max 140 chars)

**Image Optimization**:
- Format WebP with fallback JPEG
- Lazy loading natif (`loading="lazy"`)
- Placeholder blur-up technique (LQIP)

### 5. Roadmap Section
**ID**: `#roadmap`  
**Layout**: Centered vertical timeline  
**Content**:
- Phases: Q1 2024 (Research) → Q2 2024 (Testnet) → Q3 2024 (