# TSN UI 2.0 - Dynamic Design Palette & Principles

## TSN Color Palette (Extracted of the Code)

### Primary Colors
- **Noir Quantum** : `#0a0e14` — Main background, evokes the depth of cryptographic space
- **Bleu Plonky** : `#58a6ff` — TSN signature color, reference to STARK proofs
- **Violet ML-DSA** : `#a371f7` — Secondary color, evokes les post-quantum signatures
- **Gradient Signature** : `linear-gradient(135deg, #58a6ff 0%, #a371f7 100%)` — TSN visual DNA

### Structural Colors
- **Gris Translucides** : `rgba(22, 27, 34, 0.8)`, `rgba(13, 17, 23, 0.6)` — Cards, overlays
- **Bordures Subtiles** : `rgba(48, 54, 61, 0.6)` — Subtle separation
- **Primary Text** : `#e6edf3` — Maximum readability
- **Secondary Text** : `#8b949e` — Information hierarchy

## TSN Design Principles

### 1. **Technical Transparency**
The UI reflects the project philosophy : no mystery, everything is visible.
- Les effets de blur (`backdrop-filter: blur(12px)`) simulate cryptographic complexity made accessible
- Gradients create depth without hiding information

### 2. **Quantum-Safe Aesthetic**
Each color has cryptographic significance :
- **Bleu** → Plonky2 STARKs (quantum-resistant proofs)
- **Violet** → ML-DSA-65 (post-quantum signatures)
- **Noir profond** → The cryptographic possibility space

### 3. **Fluidity 60fps**
- Smooth transitions (`transition: all 0.2s ease`)
- Respectful animations (`prefers-reduced-motion`)
- Reassuring micro-interactions (hover, click feedback)

## Dynamic Visual Identity

### Logo & Typography
- **Logo** : Simple, geometric, no superfluous effects
- **Police Principale** : Inter (maximum clarity)
- **Police Mono** : JetBrains Mono (for code/cryptographic data)

### Modern Effects Implementeds
- **Glassmorphism** : `backdrop-filter: blur(12px)` + transparence
- **Glow Effects** : `box-shadow: 0 4px 20px rgba(88, 166, 255, 0.4)`
- **Gradients Animated** : Transition fluide between bleu and violet
- **Micro-animations** : `transform: translateY(-2px)` at hover

## Brand Messages for UI 2.0

### Pour Discord FR (Community TSN)
```
🎨 **TSN UI 2.0 deployed!**

Gradients fluides, animations 60fps, glassmorphism refined — notre quantum-safe wallet has never been so elegant.

Post-quantum crypto deserves UX worthy of 2026. Mission accomplished.

🔮 **Next** : Mobile app + interactive demos to democratize PQ.
```

### Pour Twitter/X EN (Audience Tech)
```
🧵 TSN just shipped the most elegant post-quantum wallet interface ever built.

Dark glassmorphism + ML-DSA signatures + 60fps animations = the future of quantum-safe UX.

When an AI team builds crypto interfaces from first principles, this is what happens.

Try it: wallet.tsn.network 🔗
```

### Pour LinkedIn FR (Professionnels)
```
💫 TSN just proved that a blockkchain post-quantum can have elegance of ae fintech 2026.

Behind every gradient, une signature ML-DSA-65. Behind every animation, une proof Plonky2 STARK.

Cryptographic innovation + design thinking = mainstream adoption.

This is our vision of responsible crypto.
```

## Usage Guidelines

### ✅ Faire
- Utiliser le gradient signature on CTA importants
- Maintenir les ratios de contraste (WCAG AA minimum)
- Preserver la fluidity 60fps sur all les devices
- Garder la consistency typographique (Inter + JetBrains Mono)

### ❌ Avoid
- Surcharger d'effets visuels (reste sobre and technique)
- Utiliser d'autres couleurs without validation brand
- Casser la hierarchy de the information
- Neglect accessibility (respect of the preferences utilisateur)

---

**TSN Signature** : *Quantum-resistant by design, elegant by choice.*