# AMOSKYS Master Navigation Index
**Date**: December 5, 2025  
**Purpose**: Single point of entry for ALL documentation  
**Status**: Complete overview with quick links

---

## 🎯 START HERE (Choose Your Path)

### If you're NEW to AMOSKYS
1. Read: `README.md` (5 min) - Project overview
2. Read: `MASTER_DEVELOPMENT_GUIDE.md` (10 min) - Architecture & setup
3. Read: `SOLO_DEVELOPER_ROADMAP.md` (15 min) - 6-week plan
4. **Go to**: "For Developers Starting Work" below

### If you're CONTINUING previous work
1. Read: `IMPLEMENTATION_PROGRESS_TRACKER.md` (5 min) - Check where you left off
2. Read: Relevant phase section from `SOLO_DEVELOPER_ROADMAP.md`
3. Execute: Steps from `QUICK_START_TODAY.md`
4. **Go to**: "For Active Development" below

### If you're DEBUGGING an issue
1. Check: `ISSUES_AND_GAPS_ASSESSMENT.md` - Known issues
2. Check: `TECHNICAL_REFERENCE.md` - Architecture & APIs
3. Check: Relevant test in `tests/component/`
4. **Go to**: "For Troubleshooting" below

### If you need CONTEXT quickly
- `TECHNICAL_REFERENCE.md` - System architecture, APIs, data structures
- `SOLO_DEVELOPER_ROADMAP.md` - High-level roadmap
- `IMPLEMENTATION_PROGRESS_TRACKER.md` - Current progress

---

## 📚 COMPLETE DOCUMENT LIBRARY

### ESSENTIAL (Must Read)
| Document | Purpose | Read Time | When |
|----------|---------|-----------|------|
| **README.md** | Project overview | 5m | First time only |
| **MASTER_DEVELOPMENT_GUIDE.md** | Setup + architecture | 10m | First time only |
| **SOLO_DEVELOPER_ROADMAP.md** | 6-week implementation plan | 15m | Start of each phase |
| **QUICK_START_TODAY.md** | Step-by-step for immediate action | 10m | Daily (before starting work) |
| **IMPLEMENTATION_PROGRESS_TRACKER.md** | Real-time task status | 5m | Daily (track progress) |

### REFERENCE
| Document | Purpose | Read Time | When |
|----------|---------|-----------|------|
| **TECHNICAL_REFERENCE.md** | Architecture, APIs, files, queries | Variable | Look up specifics |
| **ISSUES_AND_GAPS_ASSESSMENT.md** | All known problems & gaps | 15m | Planning & debugging |

### SESSION DOCUMENTS (NEW - THIS SESSION)
| Document | Purpose | Status |
|----------|---------|--------|
| ISSUES_AND_GAPS_ASSESSMENT.md | Comprehensive issues + gaps | ✅ NEW |
| IMPLEMENTATION_PROGRESS_TRACKER.md | Real-time progress tracking | ✅ NEW |
| QUICK_START_TODAY.md | Today's immediate actions | ✅ NEW |
| TECHNICAL_REFERENCE.md | Architecture quick lookup | ✅ NEW |
| MASTER_NAVIGATION_INDEX.md | This file | ✅ NEW |

### ARCHIVED (Old Session Reports)
- `.docs-archive/` folder contains 100+ historical files
- Not needed for MVP work
- Kept for historical reference only

---

## 🗺️ DOCUMENT FLOW BY TASK

### Task 1: Cleanup & Stabilization (Today)
1. Read: `QUICK_START_TODAY.md` → Complete Pre-Phase 0
2. Reference: `TECHNICAL_REFERENCE.md` → Port/service info
3. Track: `IMPLEMENTATION_PROGRESS_TRACKER.md` → Mark tasks done

### Task 2: Phase 1 (Weeks 1-2)
1. Read: `SOLO_DEVELOPER_ROADMAP.md` → Phase 1 section
2. Read: `ISSUES_AND_GAPS_ASSESSMENT.md` → Gap 3.1-3.2
3. Reference: `TECHNICAL_REFERENCE.md` → Config, metrics, startup
4. Track: `IMPLEMENTATION_PROGRESS_TRACKER.md` → Phase 1 tasks

### Task 3: Phase 2 (Weeks 2-3, Hero Slice)
1. Read: `SOLO_DEVELOPER_ROADMAP.md` → Phase 2 section
2. Read: `ISSUES_AND_GAPS_ASSESSMENT.md` → Gap 2.1-2.6
3. Reference: `TECHNICAL_REFERENCE.md` → Database queries, data structures
4. Create: `docs/HERO_SLICE_PROCESS_SNMP.md` (design contract)
5. Track: `IMPLEMENTATION_PROGRESS_TRACKER.md` → Phase 2 tasks

### Task 4: Phase 3 (Weeks 4-5, Three-Layer Brain)
1. Read: `SOLO_DEVELOPER_ROADMAP.md` → Phase 3 section
2. Read: `TECHNICAL_REFERENCE.md` → Three-layer brain architecture
3. Implement: Geometric, Temporal, Fusion engines
4. Track: `IMPLEMENTATION_PROGRESS_TRACKER.md` → Phase 3 tasks

### Task 5: Phase 4 (Week 6, Polish)
1. Read: `SOLO_DEVELOPER_ROADMAP.md` → Phase 4 section
2. Create: `docs/TRACTS.md` (vision)
3. Create: `docs/HERO_SLICE_DEMO.md` (demo walkthrough)
4. Record: Demo video
5. Track: `IMPLEMENTATION_PROGRESS_TRACKER.md` → Phase 4 tasks

---

## 🎯 FOR DEVELOPERS STARTING WORK

### Every Morning
1. Open: `QUICK_START_TODAY.md`
2. Update: `IMPLEMENTATION_PROGRESS_TRACKER.md` with yesterday's progress
3. Decide: What phase/task to work on
4. Execute: Steps from relevant document

### During Development
- **Get unstuck**: Check `TECHNICAL_REFERENCE.md` → Troubleshooting section
- **Verify architecture**: Check `TECHNICAL_REFERENCE.md` → Component diagram
- **Look up data structure**: Check `TECHNICAL_REFERENCE.md` → Data Structures section
- **Track progress**: Update `IMPLEMENTATION_PROGRESS_TRACKER.md` after each task

### Before Committing
1. Check: All tests pass
2. Update: `IMPLEMENTATION_PROGRESS_TRACKER.md` with status
3. Commit with clear message: `git commit -m "feat/fix: Task N - description"`
4. Reference: Which roadmap task (Task 2.1, etc.)

---

## 📊 FOR MANAGERS / STAKEHOLDERS

### Weekly Status Check
- Read: `IMPLEMENTATION_PROGRESS_TRACKER.md` → Overall progress section
- Check: Task completion rates by phase
- Review: Any blockers or risks

### Monthly Review
- Read: `IMPLEMENTATION_PROGRESS_TRACKER.md` → Full status
- Review: Issues & gaps from `ISSUES_AND_GAPS_ASSESSMENT.md`
- Timeline: Cross-reference `SOLO_DEVELOPER_ROADMAP.md` → weekly breakdown

### Demo Preparation (Week 6)
- Reference: `SOLO_DEVELOPER_ROADMAP.md` → Phase 4 success criteria
- Watch: Demo video (to be recorded)
- Review: `docs/HERO_SLICE_DEMO.md`

---

## 🔧 FOR DEBUGGING / TROUBLESHOOTING

### Lost? Start Here
1. **What was I doing?** → `IMPLEMENTATION_PROGRESS_TRACKER.md` (check status)
2. **What am I building?** → `SOLO_DEVELOPER_ROADMAP.md` (check phase overview)
3. **How does it work?** → `TECHNICAL_REFERENCE.md` (check architecture)
4. **What's broken?** → `ISSUES_AND_GAPS_ASSESSMENT.md` (check known issues)

### Test Failures?
1. Check: `ISSUES_AND_GAPS_ASSESSMENT.md` → Known Issues section
2. Check: `TECHNICAL_REFERENCE.md` → Troubleshooting section
3. Run: `pytest tests/component/ -v`
4. If still stuck: Review failing test code + error message

### Performance Issues?
1. Check: `TECHNICAL_REFERENCE.md` → Database queries section
2. Profile: Which service is slow? (EventBus, agents, dashboard?)
3. Log: Enable debug logging: `logging.basicConfig(level=logging.DEBUG)`

### Design Uncertainty?
1. Read: `SOLO_DEVELOPER_ROADMAP.md` → Context section for that task
2. Check: `docs/` folder for any existing design docs
3. Review: Similar implementation (check existing agents)

---

## 📋 QUICK REFERENCE TABLE

| Need | Document | Section |
|------|----------|---------|
| **Project overview** | README.md | All |
| **Setup & installation** | MASTER_DEVELOPMENT_GUIDE.md | Setup section |
| **6-week plan** | SOLO_DEVELOPER_ROADMAP.md | Phases 1-4 |
| **Start work TODAY** | QUICK_START_TODAY.md | All |
| **Track progress** | IMPLEMENTATION_PROGRESS_TRACKER.md | By phase |
| **Known issues** | ISSUES_AND_GAPS_ASSESSMENT.md | Issues 1-3 |
| **What's missing** | ISSUES_AND_GAPS_ASSESSMENT.md | Gaps 2-3 |
| **Architecture diagram** | TECHNICAL_REFERENCE.md | System Architecture |
| **API endpoints** | TECHNICAL_REFERENCE.md | API Endpoints |
| **Database schema** | TECHNICAL_REFERENCE.md | Data Structures + SQL |
| **Key files** | TECHNICAL_REFERENCE.md | Key Files Directory |
| **Service ports** | TECHNICAL_REFERENCE.md | Communication Protocols |
| **Three-layer brain** | TECHNICAL_REFERENCE.md | Three-Layer Brain Architecture |
| **Troubleshooting** | TECHNICAL_REFERENCE.md | Quick Command Reference |

---

## 🚀 PHASE-BY-PHASE NAVIGATION

### Pre-Phase 0: Cleanup (Today)
```
1. QUICK_START_TODAY.md (complete all steps)
2. IMPLEMENTATION_PROGRESS_TRACKER.md (mark Pre-Phase 0 done)
3. SOLO_DEVELOPER_ROADMAP.md (review Phase 1 overview)
```

### Phase 1: Stability (Weeks 1-2)
```
1. SOLO_DEVELOPER_ROADMAP.md (read Phase 1 section)
2. ISSUES_AND_GAPS_ASSESSMENT.md (review Issues 1.1-1.2, Gaps 3.1-3.2)
3. TECHNICAL_REFERENCE.md (look up: metrics, config, startup)
4. Implement Task 1.1 → 1.4
5. IMPLEMENTATION_PROGRESS_TRACKER.md (mark as complete)
```

### Phase 2: Hero Slice (Weeks 2-3)
```
1. SOLO_DEVELOPER_ROADMAP.md (read Phase 2 section)
2. ISSUES_AND_GAPS_ASSESSMENT.md (review Gaps 2.1-2.6)
3. TECHNICAL_REFERENCE.md (database queries, data structures)
4. Create docs/HERO_SLICE_PROCESS_SNMP.md (Task 2.1)
5. Implement features → model → API → UI (Tasks 2.2-2.4)
6. IMPLEMENTATION_PROGRESS_TRACKER.md (mark as complete)
```

### Phase 3: Three-Layer Brain (Weeks 4-5)
```
1. SOLO_DEVELOPER_ROADMAP.md (read Phase 3 section)
2. TECHNICAL_REFERENCE.md (three-layer brain architecture)
3. Implement geometric → temporal → fusion (Tasks 3.1-3.3)
4. IMPLEMENTATION_PROGRESS_TRACKER.md (mark as complete)
```

### Phase 4: Polish (Week 6)
```
1. SOLO_DEVELOPER_ROADMAP.md (read Phase 4 section)
2. IMPLEMENTATION_PROGRESS_TRACKER.md (final validation)
3. Create docs/TRACTS.md (Task 4.1)
4. Manual validation (Task 4.2)
5. Record demo (Task 4.3)
6. Commit final code
```

---

## 🎓 LEARNING PATHS

### For ML Engineer
1. Start: `ISSUES_AND_GAPS_ASSESSMENT.md` → Gap 2.3-2.4
2. Read: `SOLO_DEVELOPER_ROADMAP.md` → Task 2.2-2.3 context
3. Reference: `TECHNICAL_REFERENCE.md` → Database queries, data structures
4. Implement: Feature engineering + model training
5. Test: Notebooks + unit tests

### For Systems Engineer
1. Start: `ISSUES_AND_GAPS_ASSESSMENT.md` → Issues 1.1-1.2, Gaps 3.1-3.2
2. Read: `SOLO_DEVELOPER_ROADMAP.md` → Task 1.1-1.4
3. Reference: `TECHNICAL_REFERENCE.md` → Services, APIs, startup
4. Implement: Stability + startup script
5. Verify: All tests pass, services start cleanly

### For Full-Stack Engineer
1. Start: `SOLO_DEVELOPER_ROADMAP.md` (all phases)
2. Reference: `TECHNICAL_REFERENCE.md` (all sections)
3. Track: `IMPLEMENTATION_PROGRESS_TRACKER.md`
4. Implement: All tasks in sequence (Pre-Phase 0 → Phase 4)

---

## 📞 DECISION TREES

### "I don't know where to start"
→ Check `IMPLEMENTATION_PROGRESS_TRACKER.md` → "Overall Progress" section  
→ Find last completed task  
→ Start next task from that phase  

### "I'm stuck on a task"
1. Check: Task description in `SOLO_DEVELOPER_ROADMAP.md`
2. Check: Context section (breadcrumbs to files)
3. Check: Related issues in `ISSUES_AND_GAPS_ASSESSMENT.md`
4. Check: Troubleshooting in `TECHNICAL_REFERENCE.md`
5. Ask: What specific step is unclear?

### "I don't know if I'm done with a task"
→ Check: `SOLO_DEVELOPER_ROADMAP.md` → Task success criteria  
→ Run: `pytest tests/component/ -v` (tests should pass)  
→ Update: `IMPLEMENTATION_PROGRESS_TRACKER.md` (mark ✅)  

### "I want to understand the architecture"
→ Read: `TECHNICAL_REFERENCE.md` → System Architecture section  
→ Read: `MASTER_DEVELOPMENT_GUIDE.md` → Component Overview  
→ Check: Flow diagram in `TECHNICAL_REFERENCE.md`

### "I need to look up an API"
→ Check: `TECHNICAL_REFERENCE.md` → API Endpoints section  
→ Check: `TECHNICAL_REFERENCE.md` → Communication Protocols  
→ Look at: Existing code in `web/app/__init__.py`

### "I need database info"
→ Check: `TECHNICAL_REFERENCE.md` → Database Queries  
→ Run: Queries from reference section  
→ Export: Data using CSV export command

---

## ✅ DOCUMENT COMPLETENESS CHECKLIST

- [x] **README.md** - Project overview
- [x] **MASTER_DEVELOPMENT_GUIDE.md** - Architecture & setup
- [x] **SOLO_DEVELOPER_ROADMAP.md** - 6-week implementation plan (36.75h)
- [x] **ISSUES_AND_GAPS_ASSESSMENT.md** - All known problems (14 critical/major issues)
- [x] **IMPLEMENTATION_PROGRESS_TRACKER.md** - Task tracking by phase
- [x] **QUICK_START_TODAY.md** - Step-by-step for immediate action
- [x] **TECHNICAL_REFERENCE.md** - Architecture, APIs, data structures
- [x] **MASTER_NAVIGATION_INDEX.md** - This file

### Documentation Statistics
- **Total Documents**: 8 essential
- **Archived Files**: 80+ (in `.docs-archive/`)
- **Total Pages**: ~50 pages of documentation
- **Effort Coverage**: 100% of 6-week roadmap
- **Last Updated**: December 5, 2025

---

## 🎯 SUCCESS METRICS FOR THIS DOCUMENTATION

After using these docs, you should be able to:
1. ✅ Explain AMOSKYS architecture in 2 minutes (using `TECHNICAL_REFERENCE.md`)
2. ✅ Start any task without asking for clarification (using roadmap + reference)
3. ✅ Debug any issue using troubleshooting guide
4. ✅ Track progress clearly with progress tracker
5. ✅ Know what's done, what's pending, and what's next

---

## 📝 HOW TO UPDATE THESE DOCS

### Daily Update (Quick)
- Update `IMPLEMENTATION_PROGRESS_TRACKER.md` with task status

### After Phase Complete
- Update `IMPLEMENTATION_PROGRESS_TRACKER.md` → Phase summary
- Create new design docs (e.g., `docs/HERO_SLICE_PROCESS_SNMP.md`)

### Weekly Review
- Review all progress
- Add any new issues to `ISSUES_AND_GAPS_ASSESSMENT.md`
- Update `TECHNICAL_REFERENCE.md` with new endpoints/structures

---

## 🚀 NEXT STEPS

1. **Right Now** (5 min)
   - Read this document (you're doing it!)
   - Pick your role: Developer, Manager, or Debugger

2. **In 5 minutes** (10 min)
   - Open `QUICK_START_TODAY.md`
   - Follow Pre-Phase 0 steps

3. **By End of Day** (1-2 hours)
   - Complete cleanup steps
   - Start Phase 2.1 (design doc)
   - Mark progress in tracker

4. **Tomorrow** (8 hours)
   - Continue with Phase 2 tasks
   - Reference `TECHNICAL_REFERENCE.md` as needed
   - Update tracker daily

---

## 📞 QUICK LINKS BY FILE

| File | Purpose | Quick Link |
|------|---------|-----------|
| QUICK_START_TODAY.md | Do this right now | [Start Pre-Phase 0](QUICK_START_TODAY.md) |
| SOLO_DEVELOPER_ROADMAP.md | See 6-week plan | [View Roadmap](SOLO_DEVELOPER_ROADMAP.md) |
| IMPLEMENTATION_PROGRESS_TRACKER.md | Track progress | [Update Progress](IMPLEMENTATION_PROGRESS_TRACKER.md) |
| TECHNICAL_REFERENCE.md | Look up details | [View Reference](TECHNICAL_REFERENCE.md) |
| ISSUES_AND_GAPS_ASSESSMENT.md | Understand problems | [Review Issues](ISSUES_AND_GAPS_ASSESSMENT.md) |

---

**Last Updated**: December 5, 2025  
**Status**: Complete (ready for immediate use)  
**Next Review**: After Pre-Phase 0 completion

---

**YOU NOW HAVE EVERYTHING YOU NEED. PICK A DOCUMENT AND START.**

💪 Let's ship AMOSKYS.
