# AMOSKYS UI Deep Dive Plan

## Executive Summary

This document outlines the comprehensive UI/UX implementation plan for the AMOSKYS Neural Security Command Platform. With Phase 3 authentication infrastructure complete (261 tests passing), we now focus on building the user interface layer.

---

## Current State Analysis

### ✅ What Exists

| Component | Location | Status |
|-----------|----------|--------|
| **Landing Page** | `templates/landing.html` | Working - Matrix theme |
| **Dashboard Base** | `templates/dashboard/base.html` | 855 lines - Neural grid theme |
| **Cortex Views** | `templates/dashboard/cortex.html`, `cortex-v2.html` | Dashboard variants |
| **Agent Control** | `templates/dashboard/agent-control-panel*.html` | 3 variants |
| **System Views** | `templates/dashboard/system.html`, `neural.html`, `soc.html` | Status dashboards |
| **Mobile CSS** | `static/css/mobile-responsive.css` | Responsive styles |
| **Notifications JS** | `static/js/notifications.js` | Toast notifications |
| **Auth Templates** | `templates/auth/*.html` | ✅ **NEW** - 7 templates |
| **Auth CSS** | `static/css/auth.css` | ✅ **NEW** - Neural theme |
| **Auth JS** | `static/js/auth.js` | ✅ **NEW** - Form handling |

### ✅ Phase UI-1.1: Core Auth Templates - COMPLETE

| Template | Status | Description |
|----------|--------|-------------|
| `auth/base.html` | ✅ | Base template with neural theme |
| `auth/login.html` | ✅ | Login form with validation |
| `auth/signup.html` | ✅ | Registration with password strength |
| `auth/forgot-password.html` | ✅ | Password reset request |
| `auth/reset-password.html` | ✅ | New password form |
| `auth/verify-email.html` | ✅ | Email verification handler |
| `auth/verify-pending.html` | ✅ | Verification pending page |

### ✅ Phase UI-1.2: JavaScript Modules - COMPLETE

| Module | Status | Description |
|--------|--------|-------------|
| `auth.js` | ✅ | Form handling, API calls, validation |

### ✅ Phase UI-1.3: Flask Routes - COMPLETE

| Route | Status | Description |
|-------|--------|-------------|
| `/auth/login` | ✅ | Login page |
| `/auth/signup` | ✅ | Signup page |
| `/auth/forgot-password` | ✅ | Forgot password page |
| `/auth/reset-password` | ✅ | Reset password page |
| `/auth/verify-email` | ✅ | Email verification |
| `/auth/verify-pending` | ✅ | Verification pending |
| `/auth/logout` | ✅ | Logout redirect |

---

## Pending Work

### Phase UI-2: Dashboard Enhancement (Next Sprint)

- [ ] Add user menu/avatar to dashboard header
- [ ] Show active session info
- [ ] Add logout button functionality
- [ ] Session management panel

### Phase UI-3: User Profile

- [ ] Profile settings page
- [ ] Change password form
- [ ] Active sessions list
- [ ] Account security options

### Phase UI-4: Admin Console

- [ ] User list with search/filter
- [ ] User detail view
- [ ] Account actions (lock/unlock/deactivate)
- [ ] Audit log viewer

---

## Design System

### Neural Color Palette

```css
:root {
    /* Primary Neural Colors */
    --neural-primary: #00ff88;      /* Green - Active/Success */
    --neural-secondary: #00aaff;    /* Blue - Info/Links */
    --neural-accent: #ff6b35;       /* Orange - Warnings */
    --neural-danger: #ff3366;       /* Red - Errors/Critical */
    
    /* Background Hierarchy */
    --bg-primary: #0a0a0a;          /* Darkest - Main background */
    --bg-secondary: #1a1a1a;        /* Cards/Panels */
    --bg-tertiary: #2a2a2a;         /* Input fields */
    --bg-elevated: #333333;         /* Hover states */
    
    /* Text Hierarchy */
    --text-primary: #ffffff;
    --text-secondary: #cccccc;
    --text-muted: #888888;
    --text-link: #00aaff;
    
    /* Input States */
    --input-border: rgba(0, 255, 136, 0.3);
    --input-focus: rgba(0, 255, 136, 0.6);
    --input-error: rgba(255, 51, 102, 0.6);
}
```

### Typography

- **Primary Font**: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif
- **Code/Terminal Font**: 'Courier New', 'Monaco', 'Menlo', monospace
- **Heading Scale**: 2.5rem → 2rem → 1.5rem → 1.25rem → 1rem

### Component Patterns

1. **Neural Cards** - Rounded corners, subtle glow, glass morphism
2. **Cyber Buttons** - Outlined with hover fill animation
3. **Matrix Inputs** - Dark fields with glowing focus states
4. **Status Indicators** - Pulsing dots with color semantics

---

## Implementation Phases

### Phase UI-1: Authentication UI (Sprint Focus)

**Goal**: Complete user-facing auth flows

#### UI-1.1: Core Templates

| Template | Priority | API Integration |
|----------|----------|-----------------|
| `auth/login.html` | P0 | POST /api/auth/login |
| `auth/signup.html` | P0 | POST /api/auth/signup |
| `auth/forgot-password.html` | P0 | POST /api/auth/forgot-password |
| `auth/reset-password.html` | P0 | POST /api/auth/reset-password |
| `auth/verify-email.html` | P1 | GET /api/auth/verify-email |
| `auth/verify-pending.html` | P1 | POST /api/auth/resend-verification |

#### UI-1.2: JavaScript Modules

| Module | Purpose |
|--------|---------|
| `auth.js` | Form handling, API calls, validation |
| `session.js` | Token management, auto-refresh |
| `validation.js` | Client-side form validation |

#### UI-1.3: Protected Routes

| Route Pattern | Access Level |
|---------------|--------------|
| `/` | Public |
| `/auth/*` | Public (redirect if logged in) |
| `/dashboard/*` | Authenticated users |
| `/admin/*` | Admin role required |

---

### Phase UI-2: Dashboard Enhancement

**Goal**: Integrate auth state into existing dashboards

- Add user menu/avatar to header
- Show active session info
- Add logout functionality
- Session management panel

---

### Phase UI-3: User Profile

**Goal**: User self-service features

- Profile settings page
- Change password form
- Active sessions list
- Account security options

---

### Phase UI-4: Admin Console

**Goal**: User management for admins

- User list with search/filter
- User detail view
- Account actions (lock/unlock/deactivate)
- Audit log viewer

---

## File Structure

```
web/app/
├── templates/
│   ├── auth/
│   │   ├── base.html          # Auth page base template
│   │   ├── login.html         # Login form
│   │   ├── signup.html        # Registration form
│   │   ├── forgot-password.html
│   │   ├── reset-password.html
│   │   ├── verify-email.html
│   │   └── verify-pending.html
│   ├── dashboard/
│   │   ├── base.html          # (existing) Add user menu
│   │   ├── profile.html       # User profile
│   │   └── sessions.html      # Active sessions
│   └── admin/
│       ├── users.html         # User management
│       └── audit.html         # Audit log viewer
├── static/
│   ├── css/
│   │   ├── auth.css           # Auth page styles
│   │   └── components.css     # Reusable component styles
│   └── js/
│       ├── auth.js            # Auth flow logic
│       ├── validation.js      # Form validation
│       └── session.js         # Session management
└── routes/
    └── auth_views.py          # Template routes (not API)
```

---

## API Integration Map

### Auth Flow Sequences

```
[Login Flow]
User → login.html → auth.js → POST /api/auth/login
                              ↓
                         Set Cookie → Redirect /dashboard

[Signup Flow]
User → signup.html → auth.js → POST /api/auth/signup
                               ↓
                    → verify-pending.html → Email sent
                               ↓
User clicks link → /auth/verify?token=xxx → GET /api/auth/verify-email
                               ↓
                    → login.html (success message)

[Password Reset Flow]
User → forgot-password.html → POST /api/auth/forgot-password
                               ↓
                    → Email sent (success message)
                               ↓
User clicks link → reset-password.html?token=xxx
                               ↓
                    → POST /api/auth/reset-password
                               ↓
                    → login.html (success message)
```

---

## Security Considerations

### Client-Side

1. **CSRF Protection** - Include tokens in all forms
2. **XSS Prevention** - Escape all user content
3. **Secure Cookies** - HttpOnly, Secure, SameSite=Lax
4. **Input Validation** - Client + server side

### Rate Limiting

| Endpoint | Limit |
|----------|-------|
| Login | 5/minute per IP |
| Signup | 3/minute per IP |
| Password Reset | 3/hour per email |
| General API | 50/hour per user |

---

## Testing Strategy

### E2E Tests (Playwright/Cypress)

- [ ] Complete signup flow
- [ ] Login with valid/invalid credentials
- [ ] Password reset flow
- [ ] Session timeout handling
- [ ] Protected route access

### Visual Regression

- [ ] Auth pages match design specs
- [ ] Mobile responsive layouts
- [ ] Error state displays

---

## Timeline Estimate

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| UI-1.1 | 2 days | Auth templates |
| UI-1.2 | 1 day | JavaScript modules |
| UI-1.3 | 1 day | Route protection |
| UI-2 | 2 days | Dashboard integration |
| UI-3 | 2 days | User profile |
| UI-4 | 3 days | Admin console |

**Total**: ~11 development days

---

## Next Immediate Steps

1. ✅ Create this plan document
2. 🔄 Create `templates/auth/` directory structure
3. 🔄 Implement `login.html` with Neural theme
4. 🔄 Implement `signup.html` with validation
5. 🔄 Create `auth.js` for API integration
6. 🔄 Add Flask routes for auth views

---

*Document Version: 1.0*  
*Created: December 30, 2025*  
*Phase: 3.4 - UI Integration*
